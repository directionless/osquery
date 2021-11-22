# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(efivarMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  set(generated_file_root "${CMAKE_CURRENT_SOURCE_DIR}/generated/linux/${TARGET_PROCESSOR}")

  add_library(thirdparty_efivar
    "${library_root}/src/dp-acpi.c"
    "${library_root}/src/dp-hw.c"
    "${library_root}/src/dp-media.c"
    "${library_root}/src/dp-message.c"
    "${library_root}/src/dp.c"
    "${library_root}/src/efivar.c"
    "${library_root}/src/efivarfs.c"
    "${library_root}/src/error.c"
    "${library_root}/src/export.c"
    "${library_root}/src/guid.c"
    "${library_root}/src/guids.S"
    "${library_root}/src/lib.c"
    "${library_root}/src/vars.c"
    "${library_root}/src/loadopt.c"

    "${generated_file_root}/map/libefivar.map"
    "${generated_file_root}/code/guid-symbols.c"
  )

  set_source_files_properties(
    "${library_root}/src/export.c"

    PROPERTIES
      INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/patches"
  )

  target_link_options(thirdparty_efivar PRIVATE
    "-Wl,--version-script=${generated_file_root}/map/libefivar.map"
  )

  target_compile_definitions(thirdparty_efivar PRIVATE
    _GNU_SOURCE
  )

  target_link_libraries(thirdparty_efivar
    PRIVATE
      thirdparty_c_settings

    PUBLIC
      ${CMAKE_DL_LIBS}
  )

  target_include_directories(thirdparty_efivar PRIVATE
    "${generated_file_root}/headers"
  )

  target_include_directories(thirdparty_efivar SYSTEM INTERFACE
    "${generated_file_root}/headers"
  )

  target_include_directories(thirdparty_efivar PRIVATE
    "${library_root}/src/include"
    "${generated_file_root}/headers"
  )

  target_include_directories(thirdparty_efivar SYSTEM INTERFACE
    "${generated_file_root}/headers"
  )

  set(public_header_list
    "src/src/include/efivar/efivar.h"
    "src/src/include/efivar/efivar-dp.h"

    "src/src/include/efivar/efiboot.h"
    "src/src/include/efivar/efiboot-creator.h"
    "src/src/include/efivar/efiboot-loadopt.h"
  )

  generateIncludeNamespace(thirdparty_efivar
    "efivar"
    "FILE_ONLY"
    ${public_header_list}
  )
endfunction()

efivarMain()
