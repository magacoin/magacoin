// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "leveldb/table_builder.h"

#include <assert.h>
#include "leveldb/comparator.h"
#include "leveldb/env.h"
#include "leveldb/filter_policy.h"
#include "leveldb/options.h"
#include "table/brick_builder.h"
#include "table/filter_brick.h"
#include "table/format.h"
#include "util/coding.h"
#include "util/crc32c.h"

namespace leveldb {

struct TableBuilder::Rep {
  Options options;
  Options index_brick_options;
  WritableFile* file;
  uint64_t offset;
  Status status;
  BrickBuilder data_brick;
  BrickBuilder index_brick;
  std::string last_key;
  int64_t num_entries;
  bool closed;          // Either Finish() or Abandon() has been called.
  FilterBrickBuilder* filter_brick;

  // We do not emit the index entry for a brick until we have seen the
  // first key for the next data brick.  This allows us to use shorter
  // keys in the index brick.  For example, consider a brick boundary
  // between the keys "the quick brown fox" and "the who".  We can use
  // "the r" as the key for the index brick entry since it is >= all
  // entries in the first brick and < all entries in subsequent
  // bricks.
  //
  // Invariant: r->pending_index_entry is true only if data_brick is empty.
  bool pending_index_entry;
  BrickHandle pending_handle;  // Handle to add to index brick

  std::string compressed_output;

  Rep(const Options& opt, WritableFile* f)
      : options(opt),
        index_brick_options(opt),
        file(f),
        offset(0),
        data_brick(&options),
        index_brick(&index_brick_options),
        num_entries(0),
        closed(false),
        filter_brick(opt.filter_policy == NULL ? NULL
                     : new FilterBrickBuilder(opt.filter_policy)),
        pending_index_entry(false) {
    index_brick_options.brick_restart_interval = 1;
  }
};

TableBuilder::TableBuilder(const Options& options, WritableFile* file)
    : rep_(new Rep(options, file)) {
  if (rep_->filter_brick != NULL) {
    rep_->filter_brick->StartBrick(0);
  }
}

TableBuilder::~TableBuilder() {
  assert(rep_->closed);  // Catch errors where caller forgot to call Finish()
  delete rep_->filter_brick;
  delete rep_;
}

Status TableBuilder::ChangeOptions(const Options& options) {
  // Note: if more fields are added to Options, update
  // this function to catch changes that should not be allowed to
  // change in the middle of building a Table.
  if (options.comparator != rep_->options.comparator) {
    return Status::InvalidArgument("changing comparator while building table");
  }

  // Note that any live BrickBuilders point to rep_->options and therefore
  // will automatically pick up the updated options.
  rep_->options = options;
  rep_->index_brick_options = options;
  rep_->index_brick_options.brick_restart_interval = 1;
  return Status::OK();
}

void TableBuilder::Add(const Slice& key, const Slice& value) {
  Rep* r = rep_;
  assert(!r->closed);
  if (!ok()) return;
  if (r->num_entries > 0) {
    assert(r->options.comparator->Compare(key, Slice(r->last_key)) > 0);
  }

  if (r->pending_index_entry) {
    assert(r->data_brick.empty());
    r->options.comparator->FindShortestSeparator(&r->last_key, key);
    std::string handle_encoding;
    r->pending_handle.EncodeTo(&handle_encoding);
    r->index_brick.Add(r->last_key, Slice(handle_encoding));
    r->pending_index_entry = false;
  }

  if (r->filter_brick != NULL) {
    r->filter_brick->AddKey(key);
  }

  r->last_key.assign(key.data(), key.size());
  r->num_entries++;
  r->data_brick.Add(key, value);

  const size_t estimated_brick_size = r->data_brick.CurrentSizeEstimate();
  if (estimated_brick_size >= r->options.brick_size) {
    Flush();
  }
}

void TableBuilder::Flush() {
  Rep* r = rep_;
  assert(!r->closed);
  if (!ok()) return;
  if (r->data_brick.empty()) return;
  assert(!r->pending_index_entry);
  WriteBrick(&r->data_brick, &r->pending_handle);
  if (ok()) {
    r->pending_index_entry = true;
    r->status = r->file->Flush();
  }
  if (r->filter_brick != NULL) {
    r->filter_brick->StartBrick(r->offset);
  }
}

void TableBuilder::WriteBrick(BrickBuilder* brick, BrickHandle* handle) {
  // File format contains a sequence of bricks where each brick has:
  //    brick_data: uint8[n]
  //    type: uint8
  //    crc: uint32
  assert(ok());
  Rep* r = rep_;
  Slice raw = brick->Finish();

  Slice brick_contents;
  CompressionType type = r->options.compression;
  // TODO(postrelease): Support more compression options: zlib?
  switch (type) {
    case kNoCompression:
      brick_contents = raw;
      break;

    case kSnappyCompression: {
      std::string* compressed = &r->compressed_output;
      if (port::Snappy_Compress(raw.data(), raw.size(), compressed) &&
          compressed->size() < raw.size() - (raw.size() / 8u)) {
        brick_contents = *compressed;
      } else {
        // Snappy not supported, or compressed less than 12.5%, so just
        // store uncompressed form
        brick_contents = raw;
        type = kNoCompression;
      }
      break;
    }
  }
  WriteRawBrick(brick_contents, type, handle);
  r->compressed_output.clear();
  brick->Reset();
}

void TableBuilder::WriteRawBrick(const Slice& brick_contents,
                                 CompressionType type,
                                 BrickHandle* handle) {
  Rep* r = rep_;
  handle->set_offset(r->offset);
  handle->set_size(brick_contents.size());
  r->status = r->file->Append(brick_contents);
  if (r->status.ok()) {
    char trailer[kBrickTrailerSize];
    trailer[0] = type;
    uint32_t crc = crc32c::Value(brick_contents.data(), brick_contents.size());
    crc = crc32c::Extend(crc, trailer, 1);  // Extend crc to cover brick type
    EncodeFixed32(trailer+1, crc32c::Mask(crc));
    r->status = r->file->Append(Slice(trailer, kBrickTrailerSize));
    if (r->status.ok()) {
      r->offset += brick_contents.size() + kBrickTrailerSize;
    }
  }
}

Status TableBuilder::status() const {
  return rep_->status;
}

Status TableBuilder::Finish() {
  Rep* r = rep_;
  Flush();
  assert(!r->closed);
  r->closed = true;

  BrickHandle filter_brick_handle, metaindex_brick_handle, index_brick_handle;

  // Write filter brick
  if (ok() && r->filter_brick != NULL) {
    WriteRawBrick(r->filter_brick->Finish(), kNoCompression,
                  &filter_brick_handle);
  }

  // Write metaindex brick
  if (ok()) {
    BrickBuilder meta_index_brick(&r->options);
    if (r->filter_brick != NULL) {
      // Add mapping from "filter.Name" to location of filter data
      std::string key = "filter.";
      key.append(r->options.filter_policy->Name());
      std::string handle_encoding;
      filter_brick_handle.EncodeTo(&handle_encoding);
      meta_index_brick.Add(key, handle_encoding);
    }

    // TODO(postrelease): Add stats and other meta bricks
    WriteBrick(&meta_index_brick, &metaindex_brick_handle);
  }

  // Write index brick
  if (ok()) {
    if (r->pending_index_entry) {
      r->options.comparator->FindShortSuccessor(&r->last_key);
      std::string handle_encoding;
      r->pending_handle.EncodeTo(&handle_encoding);
      r->index_brick.Add(r->last_key, Slice(handle_encoding));
      r->pending_index_entry = false;
    }
    WriteBrick(&r->index_brick, &index_brick_handle);
  }

  // Write footer
  if (ok()) {
    Footer footer;
    footer.set_metaindex_handle(metaindex_brick_handle);
    footer.set_index_handle(index_brick_handle);
    std::string footer_encoding;
    footer.EncodeTo(&footer_encoding);
    r->status = r->file->Append(footer_encoding);
    if (r->status.ok()) {
      r->offset += footer_encoding.size();
    }
  }
  return r->status;
}

void TableBuilder::Abandon() {
  Rep* r = rep_;
  assert(!r->closed);
  r->closed = true;
}

uint64_t TableBuilder::NumEntries() const {
  return rep_->num_entries;
}

uint64_t TableBuilder::FileSize() const {
  return rep_->offset;
}

}  // namespace leveldb
