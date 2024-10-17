//
// Created by scrub on 9/17/2024.
//

#ifndef MACROS_H
#define MACROS_H
#include "../../Beacond.h"

#define ALLOC(heap, size) (Beacon->Api.HeapAlloc((heap), HEAP_ZERO_MEMORY, (size)))
#define MEMCPY(dest, src, size) (memcpy((dest), (src), (size)))
#define MEMSET(dest, c, size) (memset((dest), (c), (size)))

#define V_ALLOC(lpBuffer, size) (Beacon->Api.VirtualAlloc(GetCurrentProcess(), &(lpBuffer), 0, &(dwSizeVirtual), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
#define V_PROTECT(lpBuffer, size, access, ulOldAccess) (Beacon->Api.VirtualProtect(GetCurrentProcess(), &(lpBuffer), &(dwSizeVirtual), access, &(puOldAccessRights)));
#endif //MACROS_H
