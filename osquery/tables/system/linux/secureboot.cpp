/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/secureboot.hpp>


namespace osquery {
namespace tables {

// Linux has 2 places efivars can be accessed:
//   /sys/firmware/efi/efivars -- Single file, world readable
//   /sys/firmware/efi/vars    -- Split into attributes and data, only root
//   readable
//
// There's not much documentation about the provenance of these two
// interfaces. While the `vars` directory is more usable (having a
// split data from attributes), the benefit of not requiring root
// outweighs that.
const std::string efivarsDir = "/sys/firmware/efi/efivars/";

  Status readEfiVar(                    std::string guid,
				      std::string name,
				      std::string& efiData,
				      size_t size
				      ) {
    const std::string efivarPath = efivarsDir + name + '-' + guid;

    // failure to read _probably_ means the kernel doesn't support EFI
    // vars. This is not uncommon.
    if (!readFile(efivarPath, efiData, size).ok()) {
      return Status::success();
    }


    // First 4 bytes are attributes, so the length should be _at least_ that
    if (efiData.length() < 4) {
      TLOG << "Under read on efivar file : " << efivarPath;
      return Status(1);
    }

    return Status::success();
  }



  
void readBoolEfiVar(Row& row,
                    std::string column_name,
                    std::string guid,
                    std::string name) {
  const std::string efivarPath = efivarsDir + name + '-' + guid;

  // The first 4 bytes of efivars are attribute data, we don't need
  // that data here, so we can just ignore it. The 5th byte is a
  // boolean representation.
  std::string efiData;
  if (!readFile(efivarPath, efiData, 5).ok()) {
    // failure to read _probably_ means the kernel doesn't support EFI
    // vars. This is not uncommon.
    return;
  }

  if (efiData.length() != 5) {
    TLOG << "Under read on efivar file : " << efivarPath;
    return;
  }

  auto val = (int)(unsigned char)(efiData.back());

  switch (val) {
  case 0:
    row.emplace(column_name, "0");
    break;
  case 1:
    row.emplace(column_name, "1");
    break;
  default:
    TLOG << "Unknown value in efivar(" << efivarPath << "). Got: " << val;
    row.emplace(column_name, "-1");
    break;
  }

  return;
}

QueryData genSecureBoot(QueryContext& context) {
  QueryData results;
  Row r;

  // There's a kernel rate limit on non-root reads to the EFI
  // filesystem of 100 reads per second. We could consider adding a
  // sleep, as a means to a rate limit (this is what the efivar tool
  // does), but this seems unlikely to be an issue in normal osquery
  // use. So we do nothing, aside from note it here.
  readBoolEfiVar(r, "secure_boot", kEFIBootGUID, kEFISecureBootName);
  readBoolEfiVar(r, "setup_mode", kEFIBootGUID, kEFISetupModeName);

  results.push_back(r);
  return results;
}

QueryData genUefiBootOrder(QueryContext& context) {
  const std::string efiBootOrderPath = efivarsDir + "BootOrder-" + kEFIBootGUID;
  QueryData results;

  // The first 4 bytes of efivars are attribute data, we don't need
  // that data here, so we can just ignore it. The remainder is a list
  // of boot labels, each 2 bytes wide
  std::string efiData;

  if (!readEfiVar(kEFIBootGUID, "BootOrder", efiData, 0).ok()) {
    TLOG << "efivar BootOrder failed to read";
    return results;
  }

  if(efiData.length() % 2 != 0) {
    TLOG << "efivar BootOrder is not a multiple of 2 bytes";
    return results;
  }

  if(efiData.length() < 6 ) {
    TLOG << "efivar BootOrder is too small";
    return results;
  }

  // First 4 bytes are attributes, so we start reading at 4
  for (auto i = 4; i < efiData.length();  i+=2) {
    if (i > efiData.length()) {
      TLOG << "efivar BootOrder is not a multiple of 2 bytes";
      return results;
    }

    Row r;

    // The boot label is, I believe, stored as little-endian hex. We
    // read this as a std::string. As our subsequent uses are still
    // simple strings, we can mostly leave it as is, just pad it, 
    char bootLabel [4];
    sprintf(&bootLabel[0], "%02X%02X", efiData[i+1], efiData[i]);

    r["label"] = TEXT(bootLabel);

    
    // Also, endian? WTF

    
    // Convert these to their 4 digit numbers. It's not clear if this needs some hex or unhex conversions
    //auto unpadded = efiData[i] + efiData[i+1];
    //auto bootLabel = std::string(n_zero - std::min(4, unpadded.length()), '0') + unpadded;

    TLOG << "Got Label bige " << bootLabel << "\n";

    results.push_back(r);
  }

  return results;
}
} // namespace tables
} // namespace osquery
