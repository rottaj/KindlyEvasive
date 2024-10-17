//
// Created by scrub on 9/17/2024.
//

#ifndef HTTP_H
#define HTTP_H
#include <windows.h>
BOOL HttpDownloadPayload(IN PWCHAR wcUrl, IN DWORD dwPayloadSize, OUT PVOID *pOutBuffer, OUT PDWORD dwBytesWritten);
#endif //HTTP_H
