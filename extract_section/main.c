#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[]) {
   // usage: extract_section [executable] [section] [output file] [output header]
   if (argc != 5)
      return 1;

   HANDLE bin_handle = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

   if (bin_handle == INVALID_HANDLE_VALUE)
      return 2;

   DWORD bin_size = GetFileSize(bin_handle, NULL);
   uint8_t *bin_data = (uint8_t *)malloc(bin_size);
   DWORD bytes_read;

   if (!ReadFile(bin_handle, bin_data, bin_size, &bytes_read, NULL)) {
      CloseHandle(bin_handle);
      return 3;
   }

   CloseHandle(bin_handle);
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)bin_data;

   // technically we should rely on the magic values of the struct but I'm being lazy
#if defined(_M_IX86)
   PIMAGE_NT_HEADERS32 nt_headers = (PIMAGE_NT_HEADERS32)&bin_data[dos_header->e_lfanew];
#elif defined(_M_AMD64)
   PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)&bin_data[dos_header->e_lfanew];
#endif

   PIMAGE_SECTION_HEADER section_table = (PIMAGE_SECTION_HEADER)&bin_data[dos_header->e_lfanew+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt_headers->FileHeader.SizeOfOptionalHeader];
   PIMAGE_SECTION_HEADER section = NULL;

   uint8_t target_section[8];
   memset(&target_section[0], 0, 8);
   memcpy(&target_section[0], argv[2], strlen(argv[2]));

   for (size_t i=0; i<nt_headers->FileHeader.NumberOfSections; ++i) {
      if (memcmp(&section_table[i].Name[0], &target_section[0], 8) == 0) {
         section = &section_table[i];
         break;
      }
   }

   if (section == NULL)
      return 4;

   HANDLE dump_handle = CreateFileA(argv[3], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

   if (dump_handle == INVALID_HANDLE_VALUE)
      return 5;

   DWORD bytes_written = 0;

   if (!WriteFile(dump_handle, &bin_data[section->PointerToRawData], section->Misc.VirtualSize, &bytes_written, NULL)) {
      CloseHandle(dump_handle);
      return 6;
   }

   CloseHandle(dump_handle);
   
   HANDLE header_handle = CreateFileA(argv[4], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

   if (header_handle == INVALID_HANDLE_VALUE)
      return 7;
   
   char size_header_buffer[1024];
   snprintf(&size_header_buffer[0], 1024, "#pragma once\n#define SHELLCODE_SIZE %d\n", bin_size);

   if (!WriteFile(header_handle, &size_header_buffer[0], strlen(&size_header_buffer[0]), &bytes_written, NULL)) {
      CloseHandle(header_handle);
      return 8;
   }

   CloseHandle(header_handle);

   return 0;
}
