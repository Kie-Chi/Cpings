// ======== pcap_writer_libpcap.c ========
#include "pcap_writer.h"
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

pcap_dumper_t* pcap_dump_open_for_writing(const char* filename, pcap_t** p_pcap) {
    // libpcap 写入文件需要一个 pcap_t 句柄作为上下文
    // DLT_RAW 表示我们直接提供原始 IP 包，没有链路层头部
    pcap_t* pcap = pcap_open_dead(DLT_RAW, 65535);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_dead() failed\n");
        return NULL;
    }

    pcap_dumper_t* dumper = pcap_dump_open(pcap, filename);
    if (dumper == NULL) {
        fprintf(stderr, "pcap_dump_open() failed: %s\n", pcap_geterr(pcap));
        pcap_close(pcap);
        return NULL;
    }

    *p_pcap = pcap; // 将 pcap_t 句柄返回给调用者，以便后续关闭
    return dumper;
}

void pcap_dump_ip_packet(pcap_dumper_t* dumper, const uint8_t* ip_packet, uint32_t len) {
    if (!dumper || !ip_packet || len == 0) {
        return;
    }

    struct pcap_pkthdr header;
    struct timeval tv;
    gettimeofday(&tv, NULL);

    header.ts.tv_sec = tv.tv_sec;
    header.ts.tv_usec = tv.tv_usec;
    header.caplen = len; // 捕获长度
    header.len = len;    // 原始长度

    pcap_dump((u_char*)dumper, &header, ip_packet);
}

void pcap_dump_close_writer(pcap_dumper_t* dumper, pcap_t* pcap) {
    if (dumper) {
        pcap_dump_close(dumper);
    }
    if (pcap) {
        pcap_close(pcap);
    }
}