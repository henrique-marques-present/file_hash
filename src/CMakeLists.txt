# The Flutter tooling requires that developers have CMake 3.10 or later
# installed. You should not increase this version, as doing so will cause
# the plugin to fail to compile for some customers of the plugin.
cmake_minimum_required(VERSION 3.10)

project(file_hash_library VERSION 0.0.1 LANGUAGES C)

add_library(file_hash SHARED
  "file_hash.c"
)

set_target_properties(file_hash PROPERTIES
  PUBLIC_HEADER file_hash.h
  OUTPUT_NAME "file_hash"
)

target_compile_definitions(file_hash PUBLIC DART_SHARED_LIB)

if (ANDROID)
  # Support Android 15 16k page size
  target_link_options(file_hash PRIVATE "-Wl,-z,max-page-size=16384")
endif()
