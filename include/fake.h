#ifndef _FAKE_H_
#define _FAKE_H_

#include "common.h"
#include "network.h"
#include "util.h"
#include "dns.h"

#define LARGE_PKT_MAX_LEN 3000
#define DOMAIN_MAX_LEN 256

// 结构体，用于保存 check_payload 函数的结果
struct chkres {
    uint64_t sum; // 使用64位来防止中间和溢出
    size_t len;
};

// 结构体，用于保存 find_str_positions 函数的结果
struct findres {
    int* positions; // 动态数组，存储1或2
    size_t count;
};

size_t _build_std_resp(
    uint8_t *packet,
    size_t packet_len,
    char *qname,
    char *prefix,
    char *victim,
    char *origin_ip,
    size_t length);

size_t build_fake_resp(
    uint8_t *packet,
    size_t packet_len,
    char *qname,
    char *prefix,
    char *victim,
    char *origin_ip,
    char *attacker,
    char *fake_ip,
    size_t length);

#endif