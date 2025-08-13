#ifndef _STRATEGY_H_
#define _STRATEGY_H_

#include "sender.h"

typedef struct {
    make_packet_init init_func;
    packet_free free_func;
    make_packet_func make_func;
    void* packet_args;
} oneshot_data_t;

sender_strategy_s *create_strategy_oneshot(
    make_packet_init init_func,
    packet_free free_func,
    make_packet_func make_func,
    void* packet_args, // Args for the make_func
    send_packet_func send_func,
    void* send_args // Args for the send_func
);

#endif