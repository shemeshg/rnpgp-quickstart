cmake_minimum_required(VERSION 3.10)
project(quicktartRnp VERSION 1.0)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#include( "D:/vcpkg/scripts/buildsystems/vcpkg.cmake")
add_subdirectory(RnpCore)


add_executable(quicktartRnp 
main.cpp)
target_link_libraries(quicktartRnp RnpCore)
