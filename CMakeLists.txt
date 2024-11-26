cmake_minimum_required(VERSION 3.15)

project(shellcode C)
add_library(shellcode SHARED main.c)
add_subdirectory(extract_section)
add_subdirectory(binobj)
add_dependencies(shellcode extract_section binobj)
target_include_directories(shellcode PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}")

# setting the shellcode section RWX makes testing easier
# disable incremental linking to make the memory map similar between debug and release builds
target_link_options(shellcode PUBLIC "/SECTION:.sc,RWE" "/INCREMENTAL:NO")

# disable stack checks because we can't relocate those functions
target_compile_options(shellcode PUBLIC "/GS-")

# remove runtime checks from the build flags
string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
string(REGEX REPLACE "/RTC(su|[1su])" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

if(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
  target_compile_options(shellcode PUBLIC "/arch:IA32") # disable xmm registers
  set(SHELLCODE_TEST_VAR "_SHELLCODE_DATA")
else()
  set(SHELLCODE_TEST_VAR "SHELLCODE_DATA")
endif()

add_custom_command(TARGET shellcode
  POST_BUILD
  COMMAND "$<TARGET_FILE:extract_section>" "$<TARGET_FILE:shellcode>" .sc "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/shellcode.bin" "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/shellcode_gen.h"
  VERBATIM)

add_custom_command(TARGET shellcode
  POST_BUILD
  COMMAND "$<TARGET_FILE:binobj>" "${SHELLCODE_TEST_VAR}" 1 "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/shellcode.bin" "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/shellcode.obj"
  VERBATIM)

enable_testing()
add_executable(test_shellcode test.c)
target_include_directories(test_shellcode PUBLIC
  "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>")
add_dependencies(test_shellcode shellcode)
target_link_libraries(test_shellcode "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/shellcode.obj")
add_test(NAME test_shellcode COMMAND test_shellcode)
