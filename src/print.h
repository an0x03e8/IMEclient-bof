/* print.h — buffered beacon output. */
#ifndef IMEBOF_PRINT_H
#define IMEBOF_PRINT_H

#include "bofapi.h"

void internal_printf(const char *fmt, ...);
void printoutput(int type);

#endif
