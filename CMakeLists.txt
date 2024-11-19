cmake_minimum_required(VERSION 3.15)

project(shellcode C)
add_library(shellcode SHARED main.c)
add_subdirectory(extract_section)
add_subdirectory(binobj)
add_dependencies(shellcode extract_section binobj)
target_include_directories(shellcode PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}")

# setting the shellcode section RWX makes testing easier
target_link_options(shellcode PUBLIC "/SECTION:.sc,RWE")

# disable stack checks because we can't relocate those functions
target_compile_options(shellcode PUBLIC "/GS-")

# enable minor optimizations to optimize out the jumps
target_compile_options(shellcode PUBLIC "/O1")

# I don't know the default flags to set so we set /RTCc to make the build compatible with optimization
target_compile_options(shellcode PUBLIC "/RTCc")

# enable inline expansion so we don't generate jump funcions
target_compile_options(shellcode PUBLIC "/Ob2")

if(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
  target_compile_options(shellcode PUBLIC "/ARCH:IA32") # disable xmm registers
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
