/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <assert.h>

#include <osquery/logger.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/versioning/semantic.h>

#include <string>

#include <sqlite3.h>

namespace osquery {

// The collating function must return an integer that is negative,
// zero, or positive if the first string is less than, equal to, or
// greater than the second, respectively
int version_collate(void* userdata, // UNUSED
                    int alen,
                    const void* a,
                    int blen,
                    const void* b) {
  auto aVer = tryTo<SemanticVersion>(a);
  if (aVer.isError()) {
    LOG(INFO) << "Unable to collate <<" << a
              << ">> as version. Treating as equal\n";
    return 0;
  }

  auto bVer = tryTo<SemanticVersion>(b);
  if (bVer.isError()) {
    LOG(INFO) << "Unable to collate <<" << b
              << ">> as version. Treating as equal\n";
    return 0;
  }

  return aVer.compare(bVer);
}

void registerVersionExtensions(sqlite3* db) {
  sqlite3_create_collation(
      db,
      "VERSION",
      SQLITE_UTF8 | SQLITE_DETERMINISTIC | SQLITE_INNOCUOUS,
      nullptr,
      version_collate);
}

} // namespace osquery
