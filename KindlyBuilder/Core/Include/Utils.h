//
// Created by scrub on 10/9/2024.
//

#ifndef UTILS_H
#define UTILS_H

#include <windows.h>

void Convert_PCHAR_To_WCHAR(PCHAR pChar, WCHAR** pWideChar);

BOOL ReadFileIntoBuffer(IN OUT PVOID *pBuffer, IN PCHAR pFilePath);

#endif //UTILS_H
