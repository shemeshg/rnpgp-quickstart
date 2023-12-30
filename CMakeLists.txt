cmake_minimum_required(VERSION 3.10)
project(quicktartRnp VERSION 1.0)

add_subdirectory(RnpCore)


add_executable(quicktartRnp 
main.cpp)
target_link_libraries(quicktartRnp RnpCore)
