//
// Created by scrub on 9/24/2024.
//

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <windows.h>

BOOL XOR(IN OUT PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PCHAR bKey);
BOOL RC4Init(PBYTE s, PBYTE key, ULONG Len);
BOOL RC4(PBYTE s, PBYTE Data, ULONG Len);
#endif //ENCRYPT_H
