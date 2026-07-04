#include <sqlite3.h>

#include <cstdio>

int main()
{
    sqlite3 *db = nullptr;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) {
        std::fprintf(stderr, "service: failed to open db\n");
        return 1;
    }

    char *errMsg = nullptr;
    const int rc = sqlite3_exec(
        db,
        "CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (42);",
        nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::fprintf(stderr, "service: %s\n", errMsg ? errMsg : "error");
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return 1;
    }

    std::printf("service: SQLite %s OK\n", sqlite3_libversion());
    sqlite3_close(db);
    return 0;
}
