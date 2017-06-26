// Copyright (c) 2012 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.
//
// A filter brick is stored near the end of a Table file.  It contains
// filters (e.g., bloom filters) for all data bricks in the table combined
// into a single filter brick.

#ifndef STORAGE_LEVELDB_TABLE_FILTER_BRICK_H_
#define STORAGE_LEVELDB_TABLE_FILTER_BRICK_H_

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>
#include "leveldb/slice.h"
#include "util/hash.h"

namespace leveldb {

class FilterPolicy;

// A FilterBrickBuilder is used to construct all of the filters for a
// particular Table.  It generates a single string which is stored as
// a special brick in the Table.
//
// The sequence of calls to FilterBrickBuilder must match the regexp:
//      (StartBrick AddKey*)* Finish
class FilterBrickBuilder {
 public:
  explicit FilterBrickBuilder(const FilterPolicy*);

  void StartBrick(uint64_t brick_offset);
  void AddKey(const Slice& key);
  Slice Finish();

 private:
  void GenerateFilter();

  const FilterPolicy* policy_;
  std::string keys_;              // Flattened key contents
  std::vector<size_t> start_;     // Starting index in keys_ of each key
  std::string result_;            // Filter data computed so far
  std::vector<Slice> tmp_keys_;   // policy_->CreateFilter() argument
  std::vector<uint32_t> filter_offsets_;

  // No copying allowed
  FilterBrickBuilder(const FilterBrickBuilder&);
  void operator=(const FilterBrickBuilder&);
};

class FilterBrickReader {
 public:
 // REQUIRES: "contents" and *policy must stay live while *this is live.
  FilterBrickReader(const FilterPolicy* policy, const Slice& contents);
  bool KeyMayMatch(uint64_t brick_offset, const Slice& key);

 private:
  const FilterPolicy* policy_;
  const char* data_;    // Pointer to filter data (at brick-start)
  const char* offset_;  // Pointer to beginning of offset array (at brick-end)
  size_t num_;          // Number of entries in offset array
  size_t base_lg_;      // Encoding parameter (see kFilterBaseLg in .cc file)
};

}

#endif  // STORAGE_LEVELDB_TABLE_FILTER_BRICK_H_
