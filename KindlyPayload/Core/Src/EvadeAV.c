//
// Created by scrub on 9/18/2024.
//

#include <windows.h>
#include <stdio.h>
#include "../Include/API.h"
/*
typedef NTSTATUS (NTAPI* fnNtWaitForSingleObject) (
    IN          HANDLE              Handle,
    IN          BOOLEAN             Alertable,
    IN          PLARGE_INTEGER      Timeout);
*/
WCHAR xntdll[] = {'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', '\0'};
WCHAR xNtWaitForSingleObject[] = {'N', 't', 'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
BOOL DelayProgramExecution(FLOAT ftMinutes) {

    // Converting minutes to milliseconds
    DWORD                   dwMilliSeconds          = ftMinutes * 60000;
    HANDLE                  hEvent                  = CreateEvent(NULL, 0, 0, NULL);
    LONGLONG                Delay                   = 0;
    NTSTATUS                STATUS                  = 0;
    LARGE_INTEGER           DelayInterval           = { 0 };
    DWORD                   _T0                     = 0,
                            _T1                     = 0;


    // Converting from milliseconds to the 100-nanosecond - negative time interval
    Delay = dwMilliSeconds * 10000;
    DelayInterval.QuadPart = - Delay;

    _T0 = GetTickCount64();

    fnNtWaitForSingleObject wfso = (fnNtWaitForSingleObject)GetProcAddressC(GetModuleHandleC(xntdll), xNtWaitForSingleObject);
    // Sleeping for 'dwMilliSeconds' ms
    if ((STATUS = wfso(hEvent, FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
        return FALSE;
    }

    _T1 = GetTickCount64();

    // Slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_NtWFSO' succeeded
    if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
        return FALSE;

    CloseHandle(hEvent);

    return TRUE;
}