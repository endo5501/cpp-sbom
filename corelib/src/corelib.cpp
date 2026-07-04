#include "corelib.h"

#include <sqlite3.h>

QString corelibInfo()
{
    return QStringLiteral("corelib 1.2.0 (SQLite %1)")
        .arg(QString::fromLatin1(sqlite3_libversion()));
}
