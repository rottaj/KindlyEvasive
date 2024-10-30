//
// Created by scrub on 10/3/2024.
//
#include <windows.h>
// TODO Change names prob im lazy
BOOL XOR(IN OUT PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PCHAR pKey) { // Move to file with different algorithms
    for (size_t i = 0; i < sShellcodeSize; i++){
        pShellcode[i] = pShellcode[i] ^ pKey[0];
    }
    return TRUE;
}


/* Initialization function */
VOID RC4Init(PBYTE s, PBYTE key, ULONG Len)
{
    INT i = 0 , j = 0 ;
    CHAR k[ 256 ] = { 0 };
    UCHAR tmp = 0 ;
    for (i = 0 ; i< 256 ; i++ ) {
        s[i] = i;
        k[i] = key[i% Len];
    }
    for (i = 0 ; i< 256 ; i++ ) {
        j = (j + s[i] + k[i])% 256 ;
        tmp = s[i];
        s[i] = s[j]; // Swap s[i] and s[j]
        s[j] = tmp;
    }
}

/* Encryption and decryption */
BOOL RC4(PBYTE s, PBYTE Data, ULONG Len)
{
    INT i = 0 , j = 0 , t = 0 ;
    ULONG k = 0 ;
    UCHAR tmp;
    for (k = 0 ; k<Len; k++ ) {
        i = (i + 1 )% 256 ;
        j = (j + s[i])% 256 ;
        tmp = s[i];
        s[i] = s[j]; // Swap s[x] and s[y]
        s[j] = tmp;
        t = (s[i] + s[j])% 256 ;
        Data[k] ^= s[t];
    }
    return TRUE;
}
