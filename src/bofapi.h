/* bofapi.h — Beacon BOF API + the extra kernel32 surface */

#ifndef IMEBOF_BOFAPI_H
#define IMEBOF_BOFAPI_H

#include "../common/winlean.h"

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT extern
#endif
#ifndef WINAPI
#define WINAPI
#endif

/* ---- Beacon output API ----------------------------------------------------- */
#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR  0x0d

DECLSPEC_IMPORT void BeaconOutput(int type, char *data, int len);

DECLSPEC_IMPORT void *BeaconGetValue(char *name);
DECLSPEC_IMPORT int   BeaconAddValue(char *name, void *data);
DECLSPEC_IMPORT int   BeaconRemoveValue(char *name);

/* ---- kernel32 extras ----------------------------------------------------- */
#define OPEN_EXISTING          3u
#define INVALID_HANDLE_VALUE   ((HANDLE)(long)~0)

DECLSPEC_IMPORT HANDLE WINAPI CreateFileW(const wchar_t *lpFileName,
                                          DWORD dwDesiredAccess,
                                          DWORD dwShareMode, void *sa,
                                          DWORD dwCreationDisposition,
                                          DWORD dwFlagsAndAttributes,
                                          HANDLE hTemplateFile);
DECLSPEC_IMPORT int WINAPI ReadFile(HANDLE hFile, void *lpBuffer,
                                    DWORD nNumberOfBytesToRead,
                                    DWORD *lpNumberOfBytesRead, void *overlapped);
DECLSPEC_IMPORT int WINAPI CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT DWORD WINAPI GetLastError(void);
DECLSPEC_IMPORT DWORD WINAPI GetTickCount(void);

#endif