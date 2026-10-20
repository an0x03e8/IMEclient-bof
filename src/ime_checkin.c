/* ime_checkin.c — trigger the IME agent's config sync now (the "check-in"
 * button IMEClient exposes over the agent's net.pipe status service).
 * No arguments. */
#include "wcfpipe.h"
#include "print.h"

void go(char *args, int len)
{
    (void)args;
    (void)len;
    printoutput(wcf_checkin() ? CALLBACK_ERROR : CALLBACK_OUTPUT);
}
