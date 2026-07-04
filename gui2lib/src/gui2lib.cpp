#include "gui2lib.h"

#include <QPushButton>
#include <QTextCodec>

QString gui2libDecodeLatin1(const QByteArray &data)
{
    QTextCodec *codec = QTextCodec::codecForName("ISO-8859-1");
    return codec ? codec->toUnicode(data) : QString();
}

QWidget *gui2libCreateButton(const QString &text)
{
    return new QPushButton(text);
}
