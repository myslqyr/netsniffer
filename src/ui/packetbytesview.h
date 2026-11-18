#pragma once

#include <QPlainTextEdit>
#include <QVector>

class PacketBytesView : public QPlainTextEdit {
public:
    explicit PacketBytesView(QWidget* parent = nullptr);
    void setBytes(const QByteArray& bytes);
    void highlightBytes(qsizetype offset, qsizetype length);

private:
    QVector<int> hexPositions_;
    QVector<int> asciiPositions_;
};
