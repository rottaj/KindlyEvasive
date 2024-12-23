//
// Created by scrub on 10/1/2024.
//

#ifndef BEACONBUILDER_H
#define BEACONBUILDER_H
#include <windows.h>


#define MAX_URL_SIZE 2048

typedef enum {
    ENCRYPTION_UNKNOWN,
    ENCRYPTION_AES,
    ENCRYPTION_RC4,
    ENCRYPTION_XOR
} EncryptionMethod;

typedef enum {
    PAYLOAD_UNKNOWN,
    PAYLOAD_SHELLCODE,
    PAYLOAD_DLL,
    PAYLOAD_BEACON
} PayloadType;

typedef struct {
    // Baked-in Variabes
    SIZE_T              PayloadSize;       // Total Size of Payload (bytes)
    DWORD               ChunkCount;         // Number of chunks to seperate payload into
    SIZE_T              ChunkSize;
    EncryptionMethod    EncryptionMethod;
    PCHAR               EncryptionKey;
    PayloadType         PayloadType;
    PWCHAR              StagingURL;
    BOOL                isBeacon;
    // Local
    BOOL                isLocalPayload;
    PWCHAR              RemotePayloadURL;
    PCHAR               LocalPayloadFilePath;
    PWCHAR              PayloadOutputDirectory;

} *PBUILDER, BUILDER;

extern PBUILDER Builder;



#endif //BEACONBUILDER_H
