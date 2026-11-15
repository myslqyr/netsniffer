#pragma once

#include <QString>
#include <QStringList>
#include <QVector>

struct CaptureDevice {
    QString name;
    QString description;
    QStringList addresses;
    bool loopback = false;
};

struct DeviceList {
    QVector<CaptureDevice> devices;
    QString error;
};

DeviceList enumerateDevices();
