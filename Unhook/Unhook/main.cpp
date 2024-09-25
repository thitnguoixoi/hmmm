#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <fstream>

PTEB RtlGetThreadEnvironmentBlock(); 
unsigned char* ReadDllIntoMemory(const wchar_t* dllPath, size_t* fileSize); 
void Unhook(void* Local, void* Disk);


int main() {
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink - 0x10);

    while (pLdrDataEntry->DllBase != nullptr) {
        UNICODE_STRING dllPath = pLdrDataEntry->FullDllName;

        // Convert the UNICODE_STRING to a regular string
        wchar_t* pathBuffer = new wchar_t[dllPath.Length + 1];
        wcsncpy_s(pathBuffer, dllPath.Length + 1, dllPath.Buffer, dllPath.Length);
        pathBuffer[dllPath.Length] = L'\0';
        // Do something with the DLL path
		std::wcout << pathBuffer << std::endl; 
		int count = 0;
        for (int i = 0; i < dllPath.Length; i++) {
            if (pathBuffer[i] == L'\\' || pathBuffer[i] == L'/') {
                count++;
                if (count == 2)
                {
                    if (memcmp(&pathBuffer[i + 1], L"System32", 8) == 0 
                        || memcmp(&pathBuffer[i + 1], L"SYSTEM32", 8) == 0
                        ) {
                        HANDLE ntdllFile = CreateFileW(pathBuffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                        HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
                        LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

                        if (ntdllMappingAddress) {
                            std::wcout << L"Successfully read from DLL: " << pathBuffer << std::endl;
							Unhook(pLdrDataEntry->DllBase, ntdllMappingAddress);
                        }
                    }
                }
            }
        }
        delete[] pathBuffer;
        pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pLdrDataEntry->InMemoryOrderLinks.Flink - 0x10);
    }

}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsdword(0x16);
#endif
}

void Unhook(void* Local, void* Disk) {
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)Local;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return;
    }
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)Local + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return;
    }
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pImageNtHeaders + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER text = nullptr;
    PIMAGE_SECTION_HEADER pdata = nullptr;

	for (int i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSectionHeader->Name, ".text", 5) == 0) {
			text = pSectionHeader;
		}
        if (memcmp(pSectionHeader->Name, ".pdata", 6) == 0) {
            pdata = pSectionHeader;
        }
		pSectionHeader++;
	}
    if (!text || !pdata) {
        std::cerr << "Couldn't find .text or .pdata section" << std::endl;
        return;
    }

    // .pdata section base and size
    DWORD pdataBase = (DWORD_PTR)Local + pdata->VirtualAddress;
    DWORD pdataSize = pdata->SizeOfRawData;

    // Pointer to the first RUNTIME_FUNCTION entry
    RUNTIME_FUNCTION* pRuntimeFunction = (RUNTIME_FUNCTION*)((PBYTE)Local + pdata->VirtualAddress);
    RUNTIME_FUNCTION* pLastRuntimeFunction = (RUNTIME_FUNCTION*)((PBYTE)pRuntimeFunction + pdataSize);
	DWORD64 StartText = (DWORD64)Local + text->VirtualAddress;
	DWORD64 EndText = (DWORD64)Local + text->VirtualAddress + text->SizeOfRawData;
    // Iterate over each RUNTIME_FUNCTION entry
    while (pRuntimeFunction < pLastRuntimeFunction) {
        DWORD64 FunctionStartLocal = pRuntimeFunction->BeginAddress + (DWORD64)Local;
        DWORD64 FunctionEnd = pRuntimeFunction->EndAddress + (DWORD64)Local;
        DWORD64 FunctionStartDisk = pRuntimeFunction->BeginAddress + (DWORD64)Disk;

        SIZE_T SizeFunc = FunctionEnd - FunctionStartLocal;
        if ((FunctionStartLocal >= StartText && FunctionEnd <= EndText)) {        
            if (memcmp((void*)FunctionStartLocal, (void*)FunctionStartDisk, SizeFunc) != 0) {
                printf("true");
            }
        }
        
        pRuntimeFunction++;
    }
    printf("\n");

}