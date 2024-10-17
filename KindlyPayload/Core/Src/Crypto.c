//
// Created by scrub on 10/3/2024.
//
#include <windows.h>
// TODO Change names prob im lazy
BOOL XOR(IN OUT PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) { // Move to file with different algorithms
    for (size_t i = 0; i < sShellcodeSize; i++){
        pShellcode[i] = pShellcode[i] ^ bKey;
    }
    return TRUE;
}