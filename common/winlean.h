/* winlean.h — minimal kernel32 surface used by common */

#ifndef IMEBOF_WINLEAN_H
#define IMEBOF_WINLEAN_H

#include <stddef.h>

typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int          BOOL;
typedef void        *HANDLE;

#define CP_UTF8 65001u

HANDLE LocalAlloc(UINT uFlags, size_t uBytes);
HANDLE LocalFree(HANDLE hMem);

int WideCharToMultiByte(UINT codepage, DWORD dwFlags,
                        const wchar_t *lpWideCharStr, int cchWideChar,
                        char *lpMultiByteStr, int cbMultiByte,
                        const char *lpDefaultChar, int *lpUsedDefaultChar);
int MultiByteToWideChar(UINT codepage, DWORD dwFlags,
                        const char *lpMultiByteStr, int cbMultiByte,
                        wchar_t *lpWideCharStr, int cchWideChar);

#endif