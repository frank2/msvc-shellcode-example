#include <libqueen/pe/diskpe.hpp>

using namespace libqueen;

int main(int argc, char *argv[]) {
   if (argc != 4)
      return 1;

   auto pe = DiskPE::from_disk_image(SliceUTF8(argv[1]));

   if (pe.is_null())
      return 2;

   std::uint8_t target_section[8];
   std::memset(&target_section[0], 0, 8);
   std::memcpy(&target_section[0], argv[2], std::strlen(argv[2]));
   
   auto text_section = pe.get_section_descriptor(&target_section[0]);

   if (text_section == NULL_DESCRIPTOR)
      return 3;

   auto header = text_section.first;
   auto size = (*header).Misc.VirtualSize;
   auto slice = Slice<std::uint8_t>(text_section.second.ptr(), size);
   auto end = slice.end();

   for (end=slice.end(); *(end-1)==0xCC; --end);
   
   slice.resize((std::size_t)(end-slice.ptr()));
   auto handle = CreateFileA(argv[3], GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

   if (handle == INVALID_HANDLE_VALUE)
      return 4;

   DWORD bytes_written;

   if (!WriteFile(handle, slice.ptr(), (DWORD)slice.size(), &bytes_written, nullptr))
      return 5;

   CloseHandle(handle);
   
   return 0;
}
   
