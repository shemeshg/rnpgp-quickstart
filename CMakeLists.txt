cmake_minimum_required(VERSION 3.10)
project(find_package_test VERSION 1.0)


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(PkgConfig REQUIRED)

find_package(BZip2 REQUIRED)
find_package(ZLIB REQUIRED)

pkg_check_modules(JSONC IMPORTED_TARGET json-c12)
if(NOT JSONC_FOUND)
    pkg_check_modules(JSONC REQUIRED IMPORTED_TARGET json-c)
endif(NOT JSONC_FOUND)

add_library(JSON-C::JSON-C INTERFACE IMPORTED)
set_target_properties(JSON-C::JSON-C PROPERTIES INTERFACE_LINK_LIBRARIES PkgConfig::JSONC)

pkg_check_modules(Botan REQUIRED IMPORTED_TARGET botan-3)
add_library(Botan::Botan  INTERFACE IMPORTED)
set_target_properties(Botan::Botan PROPERTIES INTERFACE_LINK_LIBRARIES PkgConfig::Botan)

find_package(rnp REQUIRED)
include_directories(/usr/local/include)

cmake_minimum_required(VERSION 3.12)
add_executable(find_package_test 
file-utils.h
file-utils.cpp
str-utils.h
str-utils.cpp
RnpCoreDefinitions.h
find_package_test.cpp)
target_link_libraries(find_package_test rnp::librnp)
