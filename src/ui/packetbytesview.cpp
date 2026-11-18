#include "packetbytesview.h"

#include <QFontDatabase>
#include <QTextCursor>
#include <algorithm>

PacketBytesView::PacketBytesView(QWidget* parent) : QPlainTextEdit(parent)
{
    setReadOnly(true);
    setLineWrapMode(QPlainTextEdit::NoWrap);
    setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    setObjectName(QStringLiteral("packetBytes"));
}

void PacketBytesView::setBytes(const QByteArray& bytes)
{
    hexPositions_.clear();
    asciiPositions_.clear();
    hexPositions_.reserve(bytes.size());
    asciiPositions_.reserve(bytes.size());
    QString text;
    for (qsizetype line = 0; line < bytes.size(); line += 16) {
        if (line != 0) text += QLatin1Char('\n');
        text += QStringLiteral("%1  ").arg(line, 8, 16, QLatin1Char('0'));
        const auto count = std::min<qsizetype>(16, bytes.size() - line);
        for (int column = 0; column < 16; ++column) {
            if (column == 8) text += QLatin1Char(' ');
            if (column < count) {
                hexPositions_.append(text.size());
                text += QStringLiteral("%1 ").arg(static_cast<quint8>(bytes[line + column]), 2, 16, QLatin1Char('0'));
            } else {
                text += QStringLiteral("   ");
            }
        }
        text += QStringLiteral(" | ");
        for (qsizetype column = 0; column < count; ++column) {
            asciiPositions_.append(text.size());
            const auto byte = static_cast<quint8>(bytes[line + column]);
            text += byte >= 32 && byte <= 126 ? QChar(byte) : QLatin1Char('.');
        }
    }
    setExtraSelections({});
    setPlainText(text);
}

void PacketBytesView::highlightBytes(qsizetype offset, qsizetype length)
{
    QList<QTextEdit::ExtraSelection> selections;
    if (offset < 0 || length <= 0 || offset >= hexPositions_.size()
        || length > hexPositions_.size() - offset) {
        setExtraSelections(selections);
        return;
    }
    const auto addSelection = [&](int first, int last) {
        QTextEdit::ExtraSelection selection;
        selection.cursor = QTextCursor(document());
        selection.cursor.setPosition(first);
        selection.cursor.setPosition(last, QTextCursor::KeepAnchor);
        selection.format.setBackground(palette().highlight());
        selection.format.setForeground(palette().highlightedText());
        selections.append(selection);
    };
    const auto end = offset + length;
    for (auto first = offset; first < end;) {
        const auto last = std::min<qsizetype>(end, ((first / 16) + 1) * 16) - 1;
        addSelection(hexPositions_[first], hexPositions_[last] + 2);
        addSelection(asciiPositions_[first], asciiPositions_[last] + 1);
        first = last + 1;
    }
    setExtraSelections(selections);
    auto cursor = textCursor();
    cursor.setPosition(hexPositions_[offset]);
    setTextCursor(cursor);
    ensureCursorVisible();
}
