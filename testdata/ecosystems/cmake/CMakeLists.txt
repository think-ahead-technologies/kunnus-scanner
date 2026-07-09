cmake_minimum_required(VERSION 3.24)
project(firmware CXX)
include(FetchContent)
include(cmake/deps.cmake)

FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 10.2.1
)

FetchContent_Declare(zlib
  URL https://zlib.net/zlib-1.3.1.tar.gz
  URL_HASH SHA256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
)

FetchContent_MakeAvailable(fmt zlib)
