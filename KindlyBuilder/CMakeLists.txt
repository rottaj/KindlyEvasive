cmake_minimum_required(VERSION 3.28)
project(KindlyBuilder C)

set(CMAKE_C_STANDARD 11)

add_executable(KindlyBuilder KindlyBuilder.c
        Core/Include/Http.h
        Core/Src/Http.c
        Core/Include/Crypto.h
        Core/Src/Crypto.c
        Core/Include/Cmd.h
        Core/Src/Cmd.c
        KindlyBuilder.h
        Core/Src/Banner.c
        Core/Include/Banner.h
        Core/Include/Pe.h
        Core/Src/Pe.c
        Core/Src/Utils.c
        Core/Include/Utils.h)


target_link_libraries(KindlyBuilder wininet)