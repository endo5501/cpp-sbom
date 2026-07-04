#include <QApplication>

#include <corelib.h>
#include <gui1lib.h>
#include <vendorlib.h>

#include <cstdio>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    const QString info = corelibInfo();
    const QString title =
        gui1libParseTitle(QStringLiteral("<doc><title>app1</title></doc>"));

    std::printf("app1: %s / title=%s / vendorlib=%s\n",
                qPrintable(info), qPrintable(title), vendorlib_version());
    return 0;
}
