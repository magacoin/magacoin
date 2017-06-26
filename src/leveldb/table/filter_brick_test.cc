// Copyright (c) 2012 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "table/filter_brick.h"

#include "leveldb/filter_policy.h"
#include "util/coding.h"
#include "util/hash.h"
#include "util/logging.h"
#include "util/testharness.h"
#include "util/testutil.h"

namespace leveldb {

// For testing: emit an array with one hash value per key
class TestHashFilter : public FilterPolicy {
 public:
  virtual const char* Name() const {
    return "TestHashFilter";
  }

  virtual void CreateFilter(const Slice* keys, int n, std::string* dst) const {
    for (int i = 0; i < n; i++) {
      uint32_t h = Hash(keys[i].data(), keys[i].size(), 1);
      PutFixed32(dst, h);
    }
  }

  virtual bool KeyMayMatch(const Slice& key, const Slice& filter) const {
    uint32_t h = Hash(key.data(), key.size(), 1);
    for (size_t i = 0; i + 4 <= filter.size(); i += 4) {
      if (h == DecodeFixed32(filter.data() + i)) {
        return true;
      }
    }
    return false;
  }
};

class FilterBrickTest {
 public:
  TestHashFilter policy_;
};

TEST(FilterBrickTest, EmptyBuilder) {
  FilterBrickBuilder builder(&policy_);
  Slice brick = builder.Finish();
  ASSERT_EQ("\\x00\\x00\\x00\\x00\\x0b", EscapeString(brick));
  FilterBrickReader reader(&policy_, brick);
  ASSERT_TRUE(reader.KeyMayMatch(0, "foo"));
  ASSERT_TRUE(reader.KeyMayMatch(100000, "foo"));
}

TEST(FilterBrickTest, SingleChunk) {
  FilterBrickBuilder builder(&policy_);
  builder.StartBrick(100);
  builder.AddKey("foo");
  builder.AddKey("bar");
  builder.AddKey("box");
  builder.StartBrick(200);
  builder.AddKey("box");
  builder.StartBrick(300);
  builder.AddKey("hello");
  Slice brick = builder.Finish();
  FilterBrickReader reader(&policy_, brick);
  ASSERT_TRUE(reader.KeyMayMatch(100, "foo"));
  ASSERT_TRUE(reader.KeyMayMatch(100, "bar"));
  ASSERT_TRUE(reader.KeyMayMatch(100, "box"));
  ASSERT_TRUE(reader.KeyMayMatch(100, "hello"));
  ASSERT_TRUE(reader.KeyMayMatch(100, "foo"));
  ASSERT_TRUE(! reader.KeyMayMatch(100, "missing"));
  ASSERT_TRUE(! reader.KeyMayMatch(100, "other"));
}

TEST(FilterBrickTest, MultiChunk) {
  FilterBrickBuilder builder(&policy_);

  // First filter
  builder.StartBrick(0);
  builder.AddKey("foo");
  builder.StartBrick(2000);
  builder.AddKey("bar");

  // Second filter
  builder.StartBrick(3100);
  builder.AddKey("box");

  // Third filter is empty

  // Last filter
  builder.StartBrick(9000);
  builder.AddKey("box");
  builder.AddKey("hello");

  Slice brick = builder.Finish();
  FilterBrickReader reader(&policy_, brick);

  // Check first filter
  ASSERT_TRUE(reader.KeyMayMatch(0, "foo"));
  ASSERT_TRUE(reader.KeyMayMatch(2000, "bar"));
  ASSERT_TRUE(! reader.KeyMayMatch(0, "box"));
  ASSERT_TRUE(! reader.KeyMayMatch(0, "hello"));

  // Check second filter
  ASSERT_TRUE(reader.KeyMayMatch(3100, "box"));
  ASSERT_TRUE(! reader.KeyMayMatch(3100, "foo"));
  ASSERT_TRUE(! reader.KeyMayMatch(3100, "bar"));
  ASSERT_TRUE(! reader.KeyMayMatch(3100, "hello"));

  // Check third filter (empty)
  ASSERT_TRUE(! reader.KeyMayMatch(4100, "foo"));
  ASSERT_TRUE(! reader.KeyMayMatch(4100, "bar"));
  ASSERT_TRUE(! reader.KeyMayMatch(4100, "box"));
  ASSERT_TRUE(! reader.KeyMayMatch(4100, "hello"));

  // Check last filter
  ASSERT_TRUE(reader.KeyMayMatch(9000, "box"));
  ASSERT_TRUE(reader.KeyMayMatch(9000, "hello"));
  ASSERT_TRUE(! reader.KeyMayMatch(9000, "foo"));
  ASSERT_TRUE(! reader.KeyMayMatch(9000, "bar"));
}

}  // namespace leveldb

int main(int argc, char** argv) {
  return leveldb::test::RunAllTests();
}
