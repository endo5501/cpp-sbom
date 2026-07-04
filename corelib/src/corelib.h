#pragma once

#include <QString>

#if defined(CORELIB_LIBRARY)
#  define CORELIB_EXPORT __declspec(dllexport)
#else
#  define CORELIB_EXPORT __declspec(dllimport)
#endif

// 内部で SQLite (静的リンク) を使い、Qt の QString を返す
CORELIB_EXPORT QString corelibInfo();
