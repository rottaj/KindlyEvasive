//
// Created by scrub on 9/17/2024.
//

#ifndef BEACOND_H
#define BEACOND_H

#include "Core/Include/API.h"

extern WCHAR wntdll[];
extern WCHAR cGetProcessHeaps[];
extern WCHAR cHeapCreate[];
extern WCHAR cAllocateHeap[];
extern WCHAR cFreeHeap[];
extern WCHAR cDestroyHeap[];
extern WCHAR cAllocateVirtualMemory[];
extern WCHAR cProtectVirtualMemory[];
extern WCHAR cFreeVirtualMemory[];
extern WCHAR cCreateThreadEx[];
extern WCHAR cNtWaitForSingleObject[];

typedef enum {
    ENCRYPTION_UNKNOWN,
    ENCRYPTION_AES,
    ENCRYPTION_RC4,
    ENCRYPTION_XOR
} EncryptionMethod;

typedef struct {
    struct {
        fnRtlGetProcessHeaps        GetProcessHeap;
        fnRtlCreateHeap             HeapCreate;
        fnRtlAllocateHeap           HeapAlloc;
        fnRtlFreeHeap               HeapFree;
        fnRtlDestroyHeap            DestroyHeap;
        fnNtAllocateVirtualMemory   VirtualAlloc;
        fnNtProtectVirtualMemory    VirtualProtect;
        fnNtFreeVirtualMemory       VirtualFree;
        fnNtCreateThreadEx          CreateThread;
        fnNtWaitForSingleObject     WaitForSingleObject;
    } Api;
    struct {
        EncryptionMethod    EncryptionMethod;
        PCHAR                EncryptionKey;
        SIZE_T              PayloadSize;
        PCHAR               StagingURL;
        DWORD               ChunkCount;
        BOOL                isBeacon;

    } Config;
} *PBEACON_INSTANCE, BEACON_INSTANCE;

extern PBEACON_INSTANCE Beacon;

#endif //BEACOND_H
