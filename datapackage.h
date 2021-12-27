#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H

#include <QString>
#include "Format.h"


/*
 * 这个类是描述数据包信息
 * +-----+------------+
 * | type| infomation |
 * +-----+------------+
 * |  1  |    arp     |
 * +-----+------------+
 * |  2  |    icmp    |
 * +-----+------------+
 * |  3  |    tcp     |
 * +-----+------------+
 * |  4  |    udp     |
 * +-----+------------+
 * |  5  |    dns     |
 * +-----+------------+
 * |  6  |    tls     |
 * +-----+------------+
 * |  7  |    ssl     |
 * +-----+------------+
*/
class DataPackage
{
private:
    u_int data_length; // 数据包长度
    QString timeStamp; // 包裹时间戳
    QString info;      // 包简介
    int packageType;   // 类型

public:
    const u_char *pkt_content;   // 包数据的根指针

protected:
    /* 将 byteArray 转为 QString */

    static QString byteToHex(u_char*str,int size);
public:
    DataPackage();
    ~DataPackage() = default;

    // 设置包格式
    void setDataLength(unsigned int length);                    // 设置包裹长度
    void setTimeStamp(QString timeStamp);                       // 设置时间戳
    void setPackageType(int type);                              // 设置包类型
    void setPackagePointer(const u_char *pkt_content,int size); // 设置包指针
    void setPackageInfo(QString info);                          // 设置包裹信息

    // 获取包格式
    QString getDataLength();                  // 获取包裹长度
    QString getTimeStamp();                   // 获取时间戳
    QString getPackageType();                 // 获取包裹类型
    QString getInfo();                        // 获取 breif 包信息
    QString getSource();                      // 获取包的源地址
    QString getDestination();                 // 获取包裹的目的地址

    // 获取mac信息
    QString getDesMacAddr();                  // 获取目的MAC地址
    QString getSrcMacAddr();                  // 获取源MAC地址
    QString getMacType();                     // 获取MAC地址的类型

    // 获取ip信息
    QString getDesIpAddr();                   // 获取目标IP地址
    QString getSrcIpAddr();                   // 获取源IP地址
    QString getIpVersion();                   // 获取ip版本
    QString getIpHeaderLength();              // 获取ip头长度
    QString getIpTos();                       // 获取ip tos
    QString getIpTotalLength();               // 获取ip总包长
    QString getIpIdentification();            // 获取ip标识
    QString getIpFlag();                      // 获取ip标志
    QString getIpReservedBit();               // 保留位
    QString getIpDF();                        // 不要碎片
    QString getIpMF();                        // 更多片段
    QString getIpFragmentOffset();            // 获取包的偏移量
    QString getIpTTL();                       // 获取 ip ttl [生存时间]
    QString getIpProtocol();                  // 获取ip协议
    QString getIpCheckSum();                  // 获取校验和

    // 获取icmp信息
    QString getIcmpType();                    // 获取 icmp 类型
    QString getIcmpCode();                    // 获取icmp代码
    QString getIcmpCheckSum();                // 获取 icmp 校验和
    QString getIcmpIdentification();          // 获取icmp标识
    QString getIcmpSequeue();                 // 获取icmp序列
    QString getIcmpData(int size);            // 获取icmp数据

    // 获取arp信息
    QString getArpHardwareType();             // 获取 arp 硬件类型
    QString getArpProtocolType();             // 获取arp协议类型
    QString getArpHardwareLength();           // 获取arp硬件长度
    QString getArpProtocolLength();           // 获取arp协议长度
    QString getArpOperationCode();            // 获取arp操作码
    QString getArpSourceEtherAddr();          // 获取arp源以太网地址
    QString getArpSourceIpAddr();             // 获取arp源IP地址
    QString getArpDestinationEtherAddr();     // 获取arp目标以太网地址
    QString getArpDestinationIpAddr();        // 获取arp目标IP地址

    // 获取tcp信息
    QString getTcpSourcePort();               // 获取tcp源端口
    QString getTcpDestinationPort();          // 获取tcp目的端口
    QString getTcpSequence();                 // 获取tcp序列
    QString getTcpAcknowledgment();           // 得到承认
    QString getTcpHeaderLength();             // 获取tcp头长
    QString getTcpRawHeaderLength();          // 获取 tcp 原始头长度 [默认为 0x05]
    QString getTcpFlags();                    // 获取 tcp 标志
    QString getTcpPSH();                      // PSH 标志
    QString getTcpACK();                      // 确认标志
    QString getTcpSYN();                      // 同步标志
    QString getTcpURG();                      // URG 标志
    QString getTcpFIN();                      // 鳍旗
    QString getTcpRST();                      // RST标志
    QString getTcpWindowSize();               // 获取 tcp 窗口大小
    QString getTcpCheckSum();                 // 获取 tcp 校验和
    QString getTcpUrgentPointer();            // 获取tcp紧急指针
    QString getTcpOperationKind(int kind);    // 获取 tcp 选项种类
    int getTcpOperationRawKind(int offset);   // 获取 tcp 原始选项种类

    /* tcp设置部分 */
    bool getTcpOperationMSS(int offset,u_short& mss);                          // kind = 2
    bool getTcpOperationWSOPT(int offset,u_char&shit);                         // kind = 3
    bool getTcpOperationSACKP(int offset);                                     // kind = 4
    bool getTcpOperationSACK(int offset,u_char&length,QVector<u_int>&edge);    // kind = 5
    bool getTcpOperationTSPOT(int offset,u_int& value,u_int&reply);            // kind = 8

    // 获取udp信息
    QString getUdpSourcePort();               // 获取udp源端口
    QString getUdpDestinationPort();          // 获取udp目的端口
    QString getUdpDataLength();               // 获取udp数据长度
    QString getUdpCheckSum();                 // 获取 udp 校验和

    // 获取dns信息
    QString getDnsTransactionId();            // 获取 dns 事务 ID
    QString getDnsFlags();                    // 获取 dns 标志
    QString getDnsFlagsQR();                  // 获取 dns 标志 QR
    QString getDnsFlagsOpcode();              // 获取dns标志操作码
    QString getDnsFlagsAA();                  // 获取 dns 标志 AA
    QString getDnsFlagsTC();                  // 获取 dns 标志 TC
    QString getDnsFlagsRD();                  // 获取 dns 标志 RD
    QString getDnsFlagsRA();                  // 获取 dns 标志 RA
    QString getDnsFlagsZ();                   // 获取 dns 标志 Z [保留]
    QString getDnsFlagsRcode();               // 获取 dns 标志 Rcode
    QString getDnsQuestionNumber();           // 获取 dns 问题编号
    QString getDnsAnswerNumber();             // 获取 dns 答复号码
    QString getDnsAuthorityNumber();          // 获取 dns 授权号
    QString getDnsAdditionalNumber();         // 获取 dns 添加号
    void getDnsQueriesDomain(QString&name,int&Type,int&Class);
    QString getDnsDomainType(int type);
    QString getDnsDomainName(int offset);
    int getDnsAnswersDomain(int offset,QString&name1,u_short&Type,u_short& Class,u_int&ttl,u_short&dataLength,QString& name2);

    // 获取tls信息
    bool getisTlsProtocol(int offset);
    void getTlsBasicInfo(int offset,u_char&contentType,u_short&version,u_short&length);
    void getTlsClientHelloInfo(int offset,u_char&handShakeType,int& length,u_short&version,QString&random,u_char&sessionIdLength,QString&sessionId,u_short&cipherLength,QVector<u_short>&cipherSuit,u_char& cmLength,QVector<u_char>&CompressionMethod,u_short&extensionLength);
    void getTlsServerHelloInfo(int offset,u_char&handShakeType,int&length,u_short&version,QString& random,u_char&sessionIdLength,QString&sessionId,u_short&cipherSuit,u_char&compressionMethod,u_short&extensionLength);
    void getTlsServerKeyExchange(int offset,u_char&handShakeType,int&length,u_char&curveType,u_short&curveName,u_char&pubLength,QString&pubKey,u_short&sigAlgorithm,u_short&sigLength,QString&sig);
    u_short getTlsExtensionType(int offset);
    void getTlsHandshakeType(int offset,u_char&type);

    /*
     * 这些函数用于解析扩展部分
     * 扩展部分在握手部分很常见（客户端你好，服务器你好......）
     * 有一些扩展类型没有包含在内，也许你应该参考官方 API
     */
    void getTlsExtensionServerName(int offset,u_short&type,u_short&length,u_short&listLength,u_char&nameType,u_short&nameLength,QString& name);
    void getTlsExtensionSignatureAlgorithms(int offset,u_short&type,u_short&length,u_short&algorithmLength,QVector<u_short>&signatureAlgorithm);
    void getTlsExtensionSupportGroups(int offset,u_short&type,u_short&length,u_short&groupListLength,QVector<u_short>&group);
    void getTlsExtensionEcPointFormats(int offset,u_short&type,u_short&length,u_char& ecLength,QVector<u_char>&EC);
    void getTlsExtensionSessionTicket(int offset,u_short&type,u_short&length);
    void getTlsExtensionEncryptThenMac(int offset,u_short&type,u_short&length);
    void getTlsExtensionSupportVersions(int offset,u_short&type,u_short&length,u_char&supportLength,QVector<u_short>&supportVersion);
    void getTlsExtensionPskKeyExchangeModes(int offset,u_short&type,u_short&length,u_char&modeLength,QVector<u_char>&mode);
    void getTlsExtensionKeyShare(int offset,u_short&type,u_short&length,u_short&shareLength,u_short&group,u_short&exchangeLength,QString& exchange);
    void getTlsExtensionOther(int offset,u_short&type,u_short&length,QString& data);
    void getTlsExtensionExtendMasterSecret(int offset,u_short&type,u_short&length);
    void getTlsExtensionPadding(int offset,u_short&type,u_short&length,QString&data);

    /*
     * 传输数据时，一些类型会被编码，比如在扩展哈希部分使用0x01来表示MD5
     * 为了可视化显示这些类型，我们需要解码和分析
     * 这个函数用来做这些分析
     * 但是，某些类型可能是自定义类型，因此我们无法解码
     * 另外，有些规则没有包括在内，也许你应该参考官方API
     */
    // 解析编码数据
    static QString getTlsHandshakeType(int type);                          // 解析TLS握手类型
    static QString getTlsContentType(int type);                            // 解析 TLS 内容类型
    static QString getTlsVersion(int version);                             // 解析 TLS 版本
    static QString getTlsHandshakeCipherSuites(u_short code);              // 解析 TLS 密码套件
    static QString getTlsHandshakeCompression(u_char code);                // 解析 TLS 压缩
    static QString getTlsHandshakeExtension(u_short type);                 // 解析 TLS 扩展
    static QString getTlsHandshakeExtensionECPointFormat(u_char type);     // 解析 TLS EC 点格式
    static QString getTlsHandshakeExtensionSupportGroup(u_short type);     // 解析 TLS 支持组
    static QString getTlsHadshakeExtensionSignature(u_char type);          // 解析 TLS 签名
    static QString getTlsHadshakeExtensionHash(u_char type);               // 解析 TLS 哈希

};

#endif // DATAPACKAGE_H
