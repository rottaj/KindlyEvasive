//
// Created by scrub on 10/3/2024.
//
#include <windows.h>
#include <stdio.h>

DWORD align(DWORD size, DWORD align, DWORD addr){
    if (!(size % align))
        return addr + size;
    return addr + (size / align + 1) * align;
}

BOOL AddPESection(PWCHAR filepath) {
    HANDLE hFile = CreateFileW(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Invalid File Handle (AddPeSection)\n");
        return -1;
    }
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    // Allocate Buffer for File
    PVOID lpFileBuffer = LocalAlloc(LMEM_ZEROINIT, dwFileSize);
    DWORD dwBytesRead = 0;
    if (!ReadFile(hFile, lpFileBuffer, dwFileSize, &dwBytesRead, NULL)) {
        printf("[!] ReadFile Failed %lu", GetLastError());
    }
    //printf("[+] File Buffer %p\n", lpFileBuffer);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Invalid PE File");
        return -1;
    }
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(lpFileBuffer + pDosHeader->e_lfanew + sizeof(DWORD));
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(lpFileBuffer + pDosHeader->e_lfanew + sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER));
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(lpFileBuffer + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    //printf("[+] File Header Number of Sections %d\n", pFileHeader->NumberOfSections);

    // Create Section name
    ZeroMemory(&pSectionHeader[pFileHeader->NumberOfSections], sizeof(IMAGE_SECTION_HEADER)); // Change to SecureZeroMemory
    CopyMemory(&pSectionHeader[pFileHeader->NumberOfSections], ".TEST", 8);

    //lets insert all the required information about our new PE section
    // 400 is the size of the section we want
    // TODO change to 1024 and re-read carefully how this all works.
    pSectionHeader[pFileHeader->NumberOfSections].Misc.VirtualSize = align(400, pOptionalHeader->SectionAlignment, 0);
    pSectionHeader[pFileHeader->NumberOfSections].VirtualAddress = align(pSectionHeader[pFileHeader->NumberOfSections - 1].Misc.VirtualSize, pOptionalHeader->SectionAlignment, pSectionHeader[pFileHeader->NumberOfSections - 1].VirtualAddress);
    pSectionHeader[pFileHeader->NumberOfSections].SizeOfRawData = align(400, pOptionalHeader->FileAlignment, 0);
    pSectionHeader[pFileHeader->NumberOfSections].PointerToRawData = align(pSectionHeader[pFileHeader->NumberOfSections - 1].SizeOfRawData, pOptionalHeader->FileAlignment, pSectionHeader[pFileHeader->NumberOfSections - 1].PointerToRawData);

    // TODO Change to RW
    pSectionHeader[pFileHeader->NumberOfSections].Characteristics = 0xE00000E0;
    /*
        0xE00000E0 = IMAGE_SCN_MEM_WRITE |
                     IMAGE_SCN_CNT_CODE  |
                     IMAGE_SCN_CNT_UNINITIALIZED_DATA  |
                     IMAGE_SCN_MEM_EXECUTE |
                     IMAGE_SCN_CNT_INITIALIZED_DATA |
                     IMAGE_SCN_MEM_READ
    */
    SetFilePointer(hFile, pSectionHeader[pFileHeader->NumberOfSections].PointerToRawData + pSectionHeader[pFileHeader->NumberOfSections].SizeOfRawData, NULL, FILE_BEGIN);
    //end the file right here,on the last section + it's own size
    SetEndOfFile(hFile);
    //now lets change the size of the image,to correspond to our modifications
    //by adding a new section,the image size is bigger now
    pOptionalHeader->SizeOfImage = pSectionHeader[pFileHeader->NumberOfSections].VirtualAddress + pSectionHeader[pFileHeader->NumberOfSections].Misc.VirtualSize;
    //and we added a new section,so we change the NOS too
    pFileHeader->NumberOfSections += 1;
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    //and finaly,we add all the modifications to the file
    DWORD dwBytesWritten = 0;
    WriteFile(hFile, lpFileBuffer, dwFileSize, &dwBytesWritten, NULL);
    CloseHandle(hFile);

    return TRUE;
}

BOOL AddDataToSection(CONST PWCHAR filepath, CONST PCHAR data) {
    CONST HANDLE hFile = CreateFileW(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    CONST DWORD dwFileSize = GetFileSize(hFile, NULL);
    BYTE *pByte = LocalAlloc(LMEM_ZEROINIT, dwFileSize);
    DWORD dw;
    ReadFile(hFile, pByte, dwFileSize, &dw, NULL);
    CONST PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[!] Error adding data to PE Section: Invalid DOS Signature\n");
        return FALSE;
    }
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Error adding data to PE Section: Invalid NT Signature\n");
        return FALSE;
    }

    //since we added a new section,it must be the last section added,cause of the code inside
    //AddSection function,thus we must get to the last section to insert our secret data :)
    CONST PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
    CONST PIMAGE_SECTION_HEADER last = first + (nt->FileHeader.NumberOfSections - 1);

    SetFilePointer(hFile, last->PointerToRawData, NULL, FILE_BEGIN);
    //printf("Testing %ls", data);
    //WriteFile(hFile, data, (wcslen(data) * sizeof(WCHAR)), &dw, 0);
    WriteFile(hFile, data, strlen(data), &dw, 0);
    CloseHandle(hFile);
    return TRUE;
}
