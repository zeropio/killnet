#include <Windows.h>
#include <stdio.h>
#include <psapi.h>
#include <fwpmu.h>

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Psapi.lib")

#define PID_TYPE 5001
#define FILENAME_TYPE 5002
#define DELETE_TYPE 5003

GUID connectv4 = { 0xB541A65A, 0xAF05, 0x4449, { 0xAB, 0x07, 0x0C, 0x55, 0x27, 0xC0, 0xE1, 0x3A } };
GUID connectv6 = { 0x31F287DD, 0x56CE, 0x46C5, { 0x94, 0xD5, 0xF6, 0x0C, 0xFF, 0x83, 0x85, 0x18 } };
GUID recv4= { 0x28D57D4A, 0x9880, 0x4643, { 0x95, 0x42, 0x8B, 0xB6, 0x3D, 0x9D, 0x67, 0xFA } };
GUID recv6 = { 0x31D84FB5, 0xEECC, 0x441F, { 0xA8, 0x36, 0x0A, 0x4B, 0xDD, 0x66, 0xEB, 0x6C } };


// Helper function
DWORD stringToDWORD(const char* str) {
    DWORD result = 0;
    while (*str) {
        if (*str < '0' || *str > '9') {
            return 0;
        }
        result = result * 10 + (*str - '0');
        str++;
    }
    return result;
}