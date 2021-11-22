/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

extern "C" {
#include <efivar/efivar.h>
#include <efivar/efiboot.h>
}

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


  #define EFI_GLOBAL_VARIABLE \
    EFI_GUID( 0x8BE4DF61, 0x93CA, 0x11d2, 0xAA0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C)


int read_efi_variable(const char* name, uint16_t** data) {
    uint16_t *res = NULL;
    efi_guid_t guid = EFI_GLOBAL_VARIABLE;
    uint32_t attributes = 0;
    size_t data_size = 0;

    int rc;
    rc = efi_get_variable(guid, name, (uint8_t **)&res, &data_size, &attributes);
    if (rc < 0) exit(rc);
    *data = res;
    return data_size / 2;
}

#define LOAD_OPTION_ACTIVE              0x00000001

void readBootDetails(Row& row,
		     char label[4]) {
  char name[8];
  sprintf(name, "Boot%s", label);

  efi_load_option *loadopt;
  uint8_t *data = NULL;
  size_t data_size = 0;
  uint32_t attributes = 0;
  const unsigned char *description;

  if( efi_get_variable(EFI_GLOBAL_VARIABLE, name, &data, &data_size, &attributes) < 0 ){
    TLOG << "EFI: Unable to read variable " << name << "\n";
    return;
  }

  // data is a packed struct. So cast it to the efi_load_option for
  // something better formed.
  loadopt = (efi_load_option *)data;

  if (!efi_loadopt_is_valid(loadopt, data_size)) {
    TLOG << "EFI: load option for " << name << " is not valid\n";
    return;
  }

  row["active"] = INTEGER(efi_loadopt_attrs(loadopt) & LOAD_OPTION_ACTIVE ? 1 : 0);

  //description = efi_loadopt_desc(loadopt, data_size);
  row["description"] = TEXT(efi_loadopt_desc(loadopt, data_size));

  // Try to find the path
  efidp dp = NULL;
  uint16_t pathlen;
  dp = efi_loadopt_path(loadopt, data_size);
  pathlen = efi_loadopt_pathlen(loadopt, data_size);
  /*  auto rc = efidp_format_device_path(NULL, 0, dp, pathlen);
  if ( rc < 0) {
    TLOG << "EFI: bad device path\n";
    return;
  }

  */
  
  return;

}
  
QueryData genEfiBootOrder(QueryContext& context) {
  QueryData results;

  uint16_t *data = NULL;
  int length = read_efi_variable("BootOrder", &data);

  if (length < 1) {
    TLOG << "got error reading efi variable\n";
    return results;
  }
  

  for (auto i = 0; i < length; i++) {
    Row r;
    r["position"] = INTEGER(i);

    
    char label[4];
    sprintf(label, "%04x", data[i]);
    r["label"] = TEXT(label);

    readBootDetails(r, label);
    
    results.push_back(r);
  }

  

  return results;
  }
  
} // namespace tables
} // namespace osquery
