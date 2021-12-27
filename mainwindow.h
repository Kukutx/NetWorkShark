#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"
#include "capture.h"
#include "readonlydelegate.h"
#include <QVector>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    // 显示网卡
    void showNetworkCard();
    // 抓取数据包
    int capture();

private slots:
    void on_comboBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int row, int column);
    void on_lineEdit_returnPressed();
    void on_lineEdit_textChanged(const QString &arg1);
    void on_tableWidget_currentCellChanged(int currentRow, int currentColumn, int previousRow, int previousColumn);
public slots:
    void handleMessage(DataPackage data);
private:
    Ui::MainWindow *ui;
    pcap_if_t *all_devices;                 // 所有适配器设备
    pcap_if_t *device;                      // 一个适配器
    pcap_t *pointer;                        // 数据包指针
    ReadOnlyDelegate* readOnlyDelegate;     // 只读权限
    int countNumber;                        // 计数
    int rowNumber;                          // 行号
    QVector<DataPackage>data;               // 存储数据
    char errbuf[PCAP_ERRBUF_SIZE];          // 错误缓冲区
    bool isStart;                           // 线程是否启动
};
#endif // MAINWINDOW_H
