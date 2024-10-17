//
// Created by scrub on 9/17/2024.
//

#ifndef WINAPI_H
#define WINAPI_H
#include <windows.h>
#include <winternl.h>
#include "Wrappers.h"

HMODULE GetModuleHandleC(IN LPCWSTR szModuleName);

PVOID GetProcAddressC(IN HMODULE hModule, IN LPCWSTR lpProcName);

typedef HANDLE (WINAPI* fnGetCurrentProcess)();

typedef PVOID (NTAPI* fnRtlCreateHeap) (
    IN          ULONG Flags,
    IN OPTIONAL PVOID Base,
    IN OPTIONAL SIZE_T Reserve,
    IN          SIZE_T Commit,
    IN OPTIONAL PVOID  Lock,
    IN OPTIONAL PRTL_HEAP_DEFINITION RtlHeapParams);

typedef ULONG (NTAPI* fnRtlGetProcessHeaps)(
    IN          ULONG       MaxNumberOfHeaps,
    OUT         PVOID       HeapArray);

typedef PVOID (NTAPI* fnRtlAllocateHeap) (
    IN          PVOID       HeapHandle,
    IN          ULONG       Flags,
    IN          ULONG       Size);

typedef NTSTATUS (NTAPI* fnRtlFreeHeap) (
    IN          PVOID       HeapHandle,
    IN OPTIONAL ULONG       Flags,
    IN          PVOID       MemoryPointer);

typedef NTSTATUS (NTAPI* fnRtlDestroyHeap) (
    IN PVOID HeapHandle);

typedef NTSTATUS (NTAPI* fnNtAllocateVirtualMemory)(
    IN          HANDLE      ProcessHandle,
    IN OUT      PVOID       BaseAddress,
    IN          ULONG       ZeroBits,
    IN OUT      PSIZE_T     RegionSize,
    IN          ULONG       AllocationType,
    IN          ULONG       Protect);

typedef NTSTATUS (NTAPI* fnNtProtectVirtualMemory)(
    IN          HANDLE      ProcessHandle,
    IN OUT      PVOID       BaseAddress,
    IN OUT      PSIZE_T     NumberOfBytesToProtect,
    IN          ULONG       NewAccessProtection,
    OUT         PULONG      OldAccessProtection);

typedef NTSTATUS (NTAPI* fnNtFreeVirtualMemory) (
    IN          HANDLE      ProcessHandle,
    IN          PVOID       BaseAddress,
    IN OUT      PULONG      RegionSize,
    IN          ULONG       FreeType);


typedef NTSTATUS (NTAPI* fnNtCreateThreadEx)(
        OUT PHANDLE                 ThreadHandle,
        IN 	ACCESS_MASK             DesiredAccess,
        IN 	POBJECT_ATTRIBUTES      ObjectAttributes,
        IN 	HANDLE                  ProcessHandle,
        IN 	PVOID                   StartRoutine,
        IN 	PVOID                   Argument,             // set to NULL
        IN 	ULONG                   CreateFlags,          // set to NULL
        IN 	SIZE_T                  ZeroBits,             // Set to NULL
        IN 	SIZE_T                  StackSize,            // Set to NULL
        IN 	SIZE_T                  MaximumStackSize,     // Set to NULL
        IN 	PVOID                   AttributeList         // set to NULL
);

typedef NTSTATUS (NTAPI* fnNtWaitForSingleObject) (
    IN          HANDLE              Handle,
    IN          BOOLEAN             Alertable,
    IN          PLARGE_INTEGER      Timeout);


#endif //WINAPI_H
