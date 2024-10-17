//
// Created by scrub on 9/17/2024.
//
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <wchar.h>
#include <iptypes.h>
#include "../Include/Wrappers.h"


// Used for checking case-sensitive library names

// TODO move to utils or something like that
BOOL IsStringEqual (IN LPCWSTR Str1, IN LPCWSTR Str2) {

    WCHAR   lStr1	[MAX_PATH],
            lStr2	[MAX_PATH];

    int		len1	= lstrlenW(Str1),
            len2	= lstrlenW(Str2);

    int		i		= 0,
            j		= 0;

    // Checking length. We dont want to overflow the buffers
    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;

    // Converting Str1 to lower case string (lStr1)
    for (i = 0; i < len1; i++){
        lStr1[i] = (WCHAR)tolower(Str1[i]);
    }
    lStr1[i++] = L'\0'; // null terminating

    // Converting Str2 to lower case string (lStr2)
    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(Str2[j]);
    }
    lStr2[j++] = L'\0'; // null terminating

    // Comparing the lower-case strings
    if (lstrcmpiW(lStr1, lStr2) == 0)
        return TRUE;

    return FALSE;
}

HMODULE GetModuleHandleC(IN LPCWSTR szModuleName) {

    // 64 bit
    PTEB_A pTib = (PTEB_A)NtCurrentTeb();
    PEB_A* pPeb = (PPEB_A)pTib->ProcessEnvironmentBlock;
    // Getting Ldr
    PPEB_LDR_DATA		    pLdr	= (PPEB_LDR_DATA)(pPeb->Ldr);

    // Getting the first element in the linked list which contains information about the first module
    PLDR_DATA_TABLE_ENTRY	pDte	= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    while (pDte) {

        // If not null
        if (pDte->FullDllName.Length != 0) {
            // Print the DLL name
            if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
                return (HMODULE)pDte->Reserved2[0];
            }

        }
        else {
            break;
        }

        // Next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

    }
    // Return NULL if not found
    return NULL;
}

PVOID GetProcAddressC(HMODULE hModule, LPCWSTR lpProcName) {

    // Create LoadLibrary to test if module is loaded

    // IMPORTANT - Must cast handle address to PBYTE or header parsing will fail
    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if(pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        wprintf(L"Failed to Get Optional Header");
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    // Getting the function's names array pointer
    PDWORD FunctionNameArray 	= (PDWORD)(pBase + pImgExportDir->AddressOfNames);

    // Getting the function's addresses array pointer
    PDWORD FunctionAddressArray 	= (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

    // Getting the function's ordinal array pointer
    PWORD  FunctionOrdinalArray 	= (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        // Getting the name of the function
        CHAR *pFunctionName = (CHAR *) (pBase + FunctionNameArray[i]);
        int wideCharSize = MultiByteToWideChar(CP_UTF8, 0, pFunctionName, -1, NULL, 0); // TODO Create custom MultiByteToWideChar or find proxy
        WCHAR wideName[wideCharSize];
        MultiByteToWideChar(CP_UTF8, 0, pFunctionName, -1, wideName, wideCharSize);
        // Getting the address of the function
        PVOID pFunctionAddress = (PVOID) (pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
        // Getting the ordinal of the function
        //WORD wFunctionOrdinal = FunctionOrdinalArray[i];

        if (wcscmp((LPCWSTR) lpProcName, wideName) == 0) {
            // Return function address
            return pFunctionAddress;
        }
    }
    return NULL;
}