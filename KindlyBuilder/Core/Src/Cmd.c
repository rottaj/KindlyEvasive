//
// Created by scrub on 10/1/2024.
//
#include <windows.h>
#include <stdio.h>
#include "../Include/Utils.h"
#include "../../KindlyBuilder.h"

BOOL print_help() {
    printf("\n\nUsage: ./KindlyBuilder [options]\n");
    printf("\nhttps://github.com/rottaj/KindlyEvasive\n");
    printf("\nOptions:\n");
    printf("   --help                       Display this help message.\n");
    printf("   --output-dir                 Full file path including file name to output payload to. \n");
    printf("   --verbose                    Print verbose output\n");
    printf("   --debug                      Enables breakpoints and console ouput on payload file.\n");
    printf("\nEncryption Options:\n");
    printf("   --encryption-method          XOR, AES, RC4.\n");
    printf("   --encryption-key             Encryption key to be used.\n");
    printf("\nPayload Input Options: \n");
    printf("   --local-file                 Load unencrypted payload file from local computer. Argument is the full file path to the payload file.\n");
    printf("   --remote-file                Fetch unencrypted payload file from remote server. Argument is the full URL to the server hosting the payload file.\n");
    printf("\nPayload Features: \n");
    printf("   --payload-type               raw, dll, beacon\n");
    printf("   --payload-size               Size of payload (in bytes)\n");
    printf("   --dummy-fetch                Make HTTP requests to dummy API's alongside payload requests.\n");
    printf("\nPayload Delivery Options:\n");
    printf("   --staging-server             URL of web server used to host initial access payloads after build is complete.\n");
    printf("   --chunk-count                Split encrypted payload into multiple files. Example: -chunk 3 (will output 3 .bin files) \n");

    printf("\n\n");

    return TRUE;
}

// Function to convert string to EncryptionMethod
EncryptionMethod string_to_encryption_method(const char *str) {
    if (strcmp(str, "AES") == 0) return ENCRYPTION_AES;
    if (strcmp(str, "RC4") == 0) return ENCRYPTION_RC4;
    if (strcmp(str, "XOR") == 0) return ENCRYPTION_XOR;
    return ENCRYPTION_UNKNOWN;
}

EncryptionMethod string_to_payload_type(const char *str) {
    if (strcmp(str, "raw") == 0) return PAYLOAD_SHELLCODE;
    if (strcmp(str, "dll") == 0) return PAYLOAD_DLL;
    if (strcmp(str, "beacon") == 0) {Builder->isBeacon = TRUE; return PAYLOAD_BEACON;}
    return PAYLOAD_UNKNOWN;
}

int HandleArgs(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_help();
            return 0;
        }
        else if (strcmp(argv[i], "--output-dir") == 0 && (i + 1) < argc) {
            Builder->PayloadOutputDirectory = malloc(MAX_PATH);
            CHAR pTempPayloadOutputDirectory[MAX_PATH];
            strcpy(pTempPayloadOutputDirectory, argv[++i]);
            Convert_PCHAR_To_WCHAR(pTempPayloadOutputDirectory, &Builder->PayloadOutputDirectory);
        } else if (strcmp(argv[i], "--remote-file") == 0 && (i + 1) < argc) {
            Builder->RemotePayloadURL = malloc(MAX_URL_SIZE);
            CHAR tempUrl[MAX_URL_SIZE];
            strcpy(tempUrl, argv[++i]);
            Convert_PCHAR_To_WCHAR(tempUrl, &Builder->RemotePayloadURL);
        } else if (strcmp(argv[i], "--payload-size") == 0 && (i + 1) < argc) {
            Builder->PayloadSize = strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--chunk-count") == 0 && (i + 1) < argc) {
            Builder->ChunkCount = strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--encryption-method") == 0 && (i + 1) < argc) {
            Builder->EncryptionMethod = string_to_encryption_method(argv[++i]);
        } else if (strcmp(argv[i], "--payload-type") == 0 && (i + 1) < argc) {
            Builder->PayloadType = string_to_payload_type(argv[++i]);
        }else if (strcmp(argv[i], "--staging-server") == 0 && (i + 1) < argc) {
            Builder->StagingURL= malloc(MAX_URL_SIZE);
            CHAR pTempStagingURL[MAX_URL_SIZE];
            strcpy(pTempStagingURL, argv[++i]);
            Convert_PCHAR_To_WCHAR(pTempStagingURL, &Builder->StagingURL);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
        }
    }
    return 1;
}



