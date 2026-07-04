#pragma once

/* 他社から受領した DLL/LIB のヘッダ (模擬) */

#if defined(VENDORLIB_BUILD)
#  define VENDORLIB_API __declspec(dllexport)
#else
#  define VENDORLIB_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

VENDORLIB_API const char *vendorlib_version(void);
VENDORLIB_API int vendorlib_add(int a, int b);

#ifdef __cplusplus
}
#endif
