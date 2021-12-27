#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    /*
     * 请修改NetWorkshark.pro：
     * INCLUDEPATH += 你的路径/包含
     * LIBS += 你的路径/Lib/wpcap.lib libws2_32
     * 否则 IDE 会警告您找不到某些头文件！
     * 这一步实际上帮助我们将winpcap添加到我们的项目中
     */
    QApplication a(argc, argv);
    MainWindow w;
    w.setWindowTitle("NetWorkShark - @ by 2021");
    w.show();
    return a.exec();
}
