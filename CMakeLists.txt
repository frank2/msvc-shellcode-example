cmake_minimum_required(VERSION 3.15)

project(shellcode C)
add_library(shellcode SHARED main.c)
target_include_directories(shellcode PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_options(shellcode PUBLIC "/SECTION:.sc,RWE")
