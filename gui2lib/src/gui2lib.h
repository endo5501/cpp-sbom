#pragma once

#include <QByteArray>
#include <QString>

#if defined(GUI2LIB_LIBRARY)
#  define GUI2LIB_EXPORT __declspec(dllexport)
#else
#  define GUI2LIB_EXPORT __declspec(dllimport)
#endif

class QWidget;

// Qt6::Core5Compat (QTextCodec) で Latin-1 をデコードする
GUI2LIB_EXPORT QString gui2libDecodeLatin1(const QByteArray &data);

// Qt6::Widgets を使う (QPushButton を生成)。呼び出しには QApplication が必要
GUI2LIB_EXPORT QWidget *gui2libCreateButton(const QString &text);
