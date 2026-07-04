#pragma once

#include <QString>

#if defined(GUI1LIB_LIBRARY)
#  define GUI1LIB_EXPORT __declspec(dllexport)
#else
#  define GUI1LIB_EXPORT __declspec(dllimport)
#endif

class QWidget;

// Qt6::Xml (QDomDocument) で XML から <title> 要素を取り出す
GUI1LIB_EXPORT QString gui1libParseTitle(const QString &xml);

// Qt6::Widgets を使う (QLabel を生成)。呼び出しには QApplication が必要
GUI1LIB_EXPORT QWidget *gui1libCreateLabel(const QString &text);
