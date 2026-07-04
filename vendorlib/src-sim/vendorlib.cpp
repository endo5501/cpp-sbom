#include "vendorlib.h"

extern "C" {

const char *vendorlib_version(void)
{
    return "1.2.3";
}

int vendorlib_add(int a, int b)
{
    return a + b;
}

}
