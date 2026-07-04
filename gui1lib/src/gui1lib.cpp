#include "gui1lib.h"

#include <QDomDocument>
#include <QLabel>

QString gui1libParseTitle(const QString &xml)
{
    QDomDocument doc;
    if (!doc.setContent(xml))
        return QString();
    return doc.documentElement().firstChildElement(QStringLiteral("title")).text();
}

QWidget *gui1libCreateLabel(const QString &text)
{
    return new QLabel(text);
}
