//
// Created by scrub on 10/9/2024.
//

#ifndef COMMON_H
#define COMMON_H

#include <windows.h>

BOOL LoadAPI();
BOOL ParsePESection();
BOOL FetchPayload(PVOID *pPayloadBuffer);
#endif //COMMON_H
