// ======== pcap_writer_libpcap.h ========

#ifndef _PCAP_WRITER_LIBPCAP_H_
#define _PCAP_WRITER_LIBPCAP_H_

#include <pcap/pcap.h> // 引入 libpcap 的主头文件

/**
 * @brief 使用 libpcap 打开一个 pcap 文件用于写入。
 * @param filename 要创建的文件名。
 * @return 成功则返回一个 pcap_dumper_t 句柄，失败则返回 NULL。
 *         这个句柄需要和 pcap_t* 一起传递给关闭函数。
 */
pcap_dumper_t *pcap_dump_open_for_writing(const char *filename, pcap_t **p_pcap);

/**
 * @brief 将一个 IP 数据包写入 pcap 文件。
 * @param dumper pcap_dump_open_for_writing 返回的句柄。
 * @param ip_packet 指向 IP 数据包（从 IP 头开始）的指针。
 * @param len IP 数据包的长度。
 */
void pcap_dump_ip_packet(pcap_dumper_t *dumper, const uint8_t *ip_packet, uint32_t len);

/**
 * @brief 关闭 pcap dumper 和相关句柄。
 * @param dumper pcap_dump_open_for_writing 返回的句柄。
 * @param pcap pcap_dump_open_for_writing 返回的 pcap_t 指针。
 */
void pcap_dump_close_writer(pcap_dumper_t *dumper, pcap_t *pcap);

#endif // !_PCAP_WRITER_LIBPCAP_H_