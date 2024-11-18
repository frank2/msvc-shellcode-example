#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>

#include "shellcode_gen.h"

extern uint8_t SHELLCODE_DATA[];

int main(int argc, char *argv[]) {
   uint8_t *valloc_buffer = VirtualAlloc(NULL, SHELLCODE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

   if (valloc_buffer == NULL)
      return 1;

   memcpy(valloc_buffer, &SHELLCODE_DATA[0], SHELLCODE_SIZE);

   return ((int (*)(LPVOID))valloc_buffer)(GetModuleHandle(NULL)) != 0;
}

   
