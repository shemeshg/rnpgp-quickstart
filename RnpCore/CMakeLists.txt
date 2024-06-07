cmake_minimum_required(VERSION 3.15)
project(RnpCore VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(FetchContent)

FetchContent_Declare(
  rnp
  GIT_REPOSITORY https://github.com/rnpgp/rnp.git
  GIT_TAG v0.17.1
)
FetchContent_GetProperties(rnp)

if(NOT rnp_POPULATED)
  message(STATUS "Fetching rnp...")
  FetchContent_Populate(rnp)
  add_subdirectory(${rnp_SOURCE_DIR} ${rnp_BINARY_DIR})
endif()

add_library(RnpCore 

RnpCoreDefinitions.h

rnpcpp.hpp
RnpCoreParams.h 
RnpCoreParams.cpp 
RnpCoreBal.h 
RnpCoreBal.cpp 
export/RnpCoreInterface.h
export/RnpKeys.h
RnpCoreInterface.cpp
)

target_link_libraries(RnpCore PRIVATE librnp )

target_include_directories(RnpCore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/export
)

include(GNUInstallDirs)
install(TARGETS RnpCore
  RUNTIME
    DESTINATION "${CMAKE_INSTALL_BINDIR}"
    COMPONENT cli
)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
