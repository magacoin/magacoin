// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifndef STORAGE_LEVELDB_TABLE_BRICK_H_
#define STORAGE_LEVELDB_TABLE_BRICK_H_

#include <stddef.h>
#include <stdint.h>
#include "leveldb/iterator.h"

namespace leveldb {

struct BrickContents;
class Comparator;

class Brick {
 public:
  // Initialize the brick with the specified contents.
  explicit Brick(const BrickContents& contents);

  ~Brick();

  size_t size() const { return size_; }
  Iterator* NewIterator(const Comparator* comparator);

 private:
  uint32_t NumRestarts() const;

  const char* data_;
  size_t size_;
  uint32_t restart_offset_;     // Offset in data_ of restart array
  bool owned_;                  // Brick owns data_[]

  // No copying allowed
  Brick(const Brick&);
  void operator=(const Brick&);

  class Iter;
};

}  // namespace leveldb

#endif  // STORAGE_LEVELDB_TABLE_BRICK_H_
