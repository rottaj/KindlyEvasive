//
// Created by scrub on 10/9/2024.
//

#include <windows.h>
void Convert_PCHAR_To_WCHAR(PCHAR pChar, WCHAR** pWideChar) {
    // Calculate the length of the PCHAR string
    int length = MultiByteToWideChar(CP_UTF8, 0, pChar, -1, NULL, 0);
    if (length == 0) {
        // Handle error if necessary
        return;
    }

    // Allocate memory for the WCHAR string
    *pWideChar = (WCHAR*)malloc(length * sizeof(WCHAR));
    if (*pWideChar == NULL) {
        // Handle memory allocation failure
        return;
    }

    // Perform the conversion
    MultiByteToWideChar(CP_UTF8, 0, pChar, -1, *pWideChar, length);
}

// TODO Replace with file mapping?
BOOL ReadFileIntoBuffer(IN OUT PVOID *pBuffer, IN PCHAR pFilePath) {
    HANDLE hFile = CreateFileA(pFilePath, GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    PBYTE pTempBuffer = LocalAlloc(LMEM_ZEROINIT, dwFileSize);
    DWORD dwTempBytesRead = 0;
    if (!ReadFile(hFile, pTempBuffer, dwFileSize, &dwTempBytesRead, NULL)) {
        return FALSE;
    }
    *pBuffer = pTempBuffer;
    return TRUE;
}

VOID Split_File_Path(PCHAR* p, PCHAR* f, PCHAR* pf) {

}