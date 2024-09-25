set(OSQUERY_TOOLCHAIN_SYSROOT "" CACHE PATH "Path to the sysroot that contains the custom toolchain to use to compile osquery. Linux only.")

if(OSQUERY_TOOLCHAIN_SYSROOT)
  overwrite_cache_variable("CMAKE_C_COMPILER" "STRING" "${OSQUERY_TOOLCHAIN_SYSROOT}/usr/bin/clang")
  overwrite_cache_variable("CMAKE_CXX_COMPILER" "STRING" "${OSQUERY_TOOLCHAIN_SYSROOT}/usr/bin/clang++")
  overwrite_cache_variable("CMAKE_SYSROOT" "PATH" "${OSQUERY_TOOLCHAIN_SYSROOT}")
  overwrite_cache_variable("CMAKE_CXX_LINK_NO_PIE_SUPPORTED" "INTERNAL" "TRUE")
  overwrite_cache_variable("CMAKE_CXX_LINK_PIE_SUPPORTED" "INTERNAL" "TRUE")
  overwrite_cache_variable("CMAKE_C_LINK_NO_PIE_SUPPORTED" "INTERNAL" "TRUE")
  overwrite_cache_variable("CMAKE_C_LINK_PIE_SUPPORTED" "INTERNAL" "TRUE")
  overwrite_cache_variable("CMAKE_CXX_FLAGS_INIT" "STRING" "-stdlib=libc++ -gdwarf-4")
  overwrite_cache_variable("CMAKE_C_FLAGS_INIT" "STRING" "-gdwarf-4")
  overwrite_cache_variable("CMAKE_EXE_LINKER_FLAGS" "STRING" "-stdlib=libc++ -lc++abi")
else()
  option(OSQUERY_STATIC_BUILD "Whether to prefer linking static libraries or not")

  overwrite_cache_variable("CMAKE_LINK_SEARCH_START_STATIC" "BOOL" "${OSQUERY_STATIC_BUILD}")
  overwrite_cache_variable("CMAKE_LINK_SEARCH_END_STATIC" "BOOL" "${OSQUERY_STATIC_BUILD}")
endif()
