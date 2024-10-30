//
// Created by scrub on 10/3/2024.
//

#ifndef CRYPTO_H
#define CRYPTO_H

#include <windows.h>

BOOL XOR(IN OUT PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PCHAR bKey);
BOOL RC4Init(PBYTE s, PBYTE key, ULONG Len);
BOOL RC4(PBYTE s, PBYTE Data, ULONG Len);
#endif //CRYPTO_H
