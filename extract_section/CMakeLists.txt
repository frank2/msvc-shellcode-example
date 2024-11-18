cmake_minimum_required(VERSION 3.15)

project(extract_section CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(NOT TARGET libqueen)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../../libqueen" "${CMAKE_BINARY_DIR}/libqueen")
endif()

add_executable(extract_section main.cpp)
target_link_libraries(extract_section libqueen)
