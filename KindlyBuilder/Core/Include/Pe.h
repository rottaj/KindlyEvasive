//
// Created by scrub on 10/3/2024.
//

#ifndef PE_H
#define PE_H

#include <windows.h>

BOOL AddDataToSection(PCHAR filepath, PCHAR data);
BOOL AddPESection(PCHAR filepath);

#endif //PE_H
