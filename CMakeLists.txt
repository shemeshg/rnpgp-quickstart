cmake_minimum_required(VERSION 3.10)
project(find_package_test VERSION 1.0)

add_subdirectory(RnpCore)


add_executable(find_package_test 
main.cpp)
target_link_libraries(find_package_test RnpCore)
