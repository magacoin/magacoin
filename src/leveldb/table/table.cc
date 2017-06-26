// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "leveldb/table.h"

#include "leveldb/cache.h"
#include "leveldb/comparator.h"
#include "leveldb/env.h"
#include "leveldb/filter_policy.h"
#include "leveldb/options.h"
#include "table/brick.h"
#include "table/filter_brick.h"
#include "table/format.h"
#include "table/two_level_iterator.h"
#include "util/coding.h"

namespace leveldb {

struct Table::Rep {
  ~Rep() {
    delete filter;
    delete [] filter_data;
    delete index_brick;
  }

  Options options;
  Status status;
  RandomAccessFile* file;
  uint64_t cache_id;
  FilterBrickReader* filter;
  const char* filter_data;

  BrickHandle metaindex_handle;  // Handle to metaindex_brick: saved from footer
  Brick* index_brick;
};

Status Table::Open(const Options& options,
                   RandomAccessFile* file,
                   uint64_t size,
                   Table** table) {
  *table = NULL;
  if (size < Footer::kEncodedLength) {
    return Status::Corruption("file is too short to be an sstable");
  }

  char footer_space[Footer::kEncodedLength];
  Slice footer_input;
  Status s = file->Read(size - Footer::kEncodedLength, Footer::kEncodedLength,
                        &footer_input, footer_space);
  if (!s.ok()) return s;

  Footer footer;
  s = footer.DecodeFrom(&footer_input);
  if (!s.ok()) return s;

  // Read the index brick
  BrickContents contents;
  Brick* index_brick = NULL;
  if (s.ok()) {
    ReadOptions opt;
    if (options.paranoid_checks) {
      opt.verify_checksums = true;
    }
    s = ReadBrick(file, opt, footer.index_handle(), &contents);
    if (s.ok()) {
      index_brick = new Brick(contents);
    }
  }

  if (s.ok()) {
    // We've successfully read the footer and the index brick: we're
    // ready to serve requests.
    Rep* rep = new Table::Rep;
    rep->options = options;
    rep->file = file;
    rep->metaindex_handle = footer.metaindex_handle();
    rep->index_brick = index_brick;
    rep->cache_id = (options.brick_cache ? options.brick_cache->NewId() : 0);
    rep->filter_data = NULL;
    rep->filter = NULL;
    *table = new Table(rep);
    (*table)->ReadMeta(footer);
  } else {
    if (index_brick) delete index_brick;
  }

  return s;
}

void Table::ReadMeta(const Footer& footer) {
  if (rep_->options.filter_policy == NULL) {
    return;  // Do not need any metadata
  }

  // TODO(sanjay): Skip this if footer.metaindex_handle() size indicates
  // it is an empty brick.
  ReadOptions opt;
  if (rep_->options.paranoid_checks) {
    opt.verify_checksums = true;
  }
  BrickContents contents;
  if (!ReadBrick(rep_->file, opt, footer.metaindex_handle(), &contents).ok()) {
    // Do not propagate errors since meta info is not needed for operation
    return;
  }
  Brick* meta = new Brick(contents);

  Iterator* iter = meta->NewIterator(BytewiseComparator());
  std::string key = "filter.";
  key.append(rep_->options.filter_policy->Name());
  iter->Seek(key);
  if (iter->Valid() && iter->key() == Slice(key)) {
    ReadFilter(iter->value());
  }
  delete iter;
  delete meta;
}

void Table::ReadFilter(const Slice& filter_handle_value) {
  Slice v = filter_handle_value;
  BrickHandle filter_handle;
  if (!filter_handle.DecodeFrom(&v).ok()) {
    return;
  }

  // We might want to unify with ReadBrick() if we start
  // requiring checksum verification in Table::Open.
  ReadOptions opt;
  if (rep_->options.paranoid_checks) {
    opt.verify_checksums = true;
  }
  BrickContents brick;
  if (!ReadBrick(rep_->file, opt, filter_handle, &brick).ok()) {
    return;
  }
  if (brick.heap_allocated) {
    rep_->filter_data = brick.data.data();     // Will need to delete later
  }
  rep_->filter = new FilterBrickReader(rep_->options.filter_policy, brick.data);
}

Table::~Table() {
  delete rep_;
}

static void DeleteBrick(void* arg, void* ignored) {
  delete reinterpret_cast<Brick*>(arg);
}

static void DeleteCachedBrick(const Slice& key, void* value) {
  Brick* brick = reinterpret_cast<Brick*>(value);
  delete brick;
}

static void ReleaseBrick(void* arg, void* h) {
  Cache* cache = reinterpret_cast<Cache*>(arg);
  Cache::Handle* handle = reinterpret_cast<Cache::Handle*>(h);
  cache->Release(handle);
}

// Convert an index iterator value (i.e., an encoded BrickHandle)
// into an iterator over the contents of the corresponding brick.
Iterator* Table::BrickReader(void* arg,
                             const ReadOptions& options,
                             const Slice& index_value) {
  Table* table = reinterpret_cast<Table*>(arg);
  Cache* brick_cache = table->rep_->options.brick_cache;
  Brick* brick = NULL;
  Cache::Handle* cache_handle = NULL;

  BrickHandle handle;
  Slice input = index_value;
  Status s = handle.DecodeFrom(&input);
  // We intentionally allow extra stuff in index_value so that we
  // can add more features in the future.

  if (s.ok()) {
    BrickContents contents;
    if (brick_cache != NULL) {
      char cache_key_buffer[16];
      EncodeFixed64(cache_key_buffer, table->rep_->cache_id);
      EncodeFixed64(cache_key_buffer+8, handle.offset());
      Slice key(cache_key_buffer, sizeof(cache_key_buffer));
      cache_handle = brick_cache->Lookup(key);
      if (cache_handle != NULL) {
        brick = reinterpret_cast<Brick*>(brick_cache->Value(cache_handle));
      } else {
        s = ReadBrick(table->rep_->file, options, handle, &contents);
        if (s.ok()) {
          brick = new Brick(contents);
          if (contents.cachable && options.fill_cache) {
            cache_handle = brick_cache->Insert(
                key, brick, brick->size(), &DeleteCachedBrick);
          }
        }
      }
    } else {
      s = ReadBrick(table->rep_->file, options, handle, &contents);
      if (s.ok()) {
        brick = new Brick(contents);
      }
    }
  }

  Iterator* iter;
  if (brick != NULL) {
    iter = brick->NewIterator(table->rep_->options.comparator);
    if (cache_handle == NULL) {
      iter->RegisterCleanup(&DeleteBrick, brick, NULL);
    } else {
      iter->RegisterCleanup(&ReleaseBrick, brick_cache, cache_handle);
    }
  } else {
    iter = NewErrorIterator(s);
  }
  return iter;
}

Iterator* Table::NewIterator(const ReadOptions& options) const {
  return NewTwoLevelIterator(
      rep_->index_brick->NewIterator(rep_->options.comparator),
      &Table::BrickReader, const_cast<Table*>(this), options);
}

Status Table::InternalGet(const ReadOptions& options, const Slice& k,
                          void* arg,
                          void (*saver)(void*, const Slice&, const Slice&)) {
  Status s;
  Iterator* iiter = rep_->index_brick->NewIterator(rep_->options.comparator);
  iiter->Seek(k);
  if (iiter->Valid()) {
    Slice handle_value = iiter->value();
    FilterBrickReader* filter = rep_->filter;
    BrickHandle handle;
    if (filter != NULL &&
        handle.DecodeFrom(&handle_value).ok() &&
        !filter->KeyMayMatch(handle.offset(), k)) {
      // Not found
    } else {
      Iterator* brick_iter = BrickReader(this, options, iiter->value());
      brick_iter->Seek(k);
      if (brick_iter->Valid()) {
        (*saver)(arg, brick_iter->key(), brick_iter->value());
      }
      s = brick_iter->status();
      delete brick_iter;
    }
  }
  if (s.ok()) {
    s = iiter->status();
  }
  delete iiter;
  return s;
}


uint64_t Table::ApproximateOffsetOf(const Slice& key) const {
  Iterator* index_iter =
      rep_->index_brick->NewIterator(rep_->options.comparator);
  index_iter->Seek(key);
  uint64_t result;
  if (index_iter->Valid()) {
    BrickHandle handle;
    Slice input = index_iter->value();
    Status s = handle.DecodeFrom(&input);
    if (s.ok()) {
      result = handle.offset();
    } else {
      // Strange: we can't decode the brick handle in the index brick.
      // We'll just return the offset of the metaindex brick, which is
      // close to the whole file size for this case.
      result = rep_->metaindex_handle.offset();
    }
  } else {
    // key is past the last key in the file.  Approximate the offset
    // by returning the offset of the metaindex brick (which is
    // right near the end of the file).
    result = rep_->metaindex_handle.offset();
  }
  delete index_iter;
  return result;
}

}  // namespace leveldb
