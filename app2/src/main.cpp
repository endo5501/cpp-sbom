#include <QApplication>
#include <QHostAddress>

#include <corelib.h>
#include <gui2lib.h>
#include <vendorlib.h>

#include <cstdio>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    const QString info = corelibInfo();
    const QString decoded = gui2libDecodeLatin1(QByteArrayLiteral("app2"));
    const QHostAddress addr(QStringLiteral("127.0.0.1"));

    std::printf("app2: %s / decoded=%s / addr=%s / vendorlib_add(2,3)=%d\n",
                qPrintable(info), qPrintable(decoded),
                qPrintable(addr.toString()), vendorlib_add(2, 3));
    return 0;
}
