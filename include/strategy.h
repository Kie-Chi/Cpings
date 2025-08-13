#ifndef _STRATEGY_H_
#define _STRATEGY_H_

#include "sender.h"
#define PPS_TIMER_INTERVAL_MS 100

typedef struct {
    default_strategy_data_t default_data;

    // More Options
} oneshot_data_t;    

typedef struct pps_data_s {
    default_strategy_data_t default_data;

    // PPS-specific fields
    uv_timer_t pps_timer;
    uint32_t pps;
    size_t high_watermark;

    packet_queue_t* private_queue;
    volatile size_t private_queue_size;
    volatile bool producing;

    pthread_mutex_t buffer_mutex;
    sender_t* sender_handle;

} pps_data_t;

typedef struct burst_data_s {
    default_strategy_data_t default_data;

    // Burst-specific fields
    uv_timer_t burst_timer;
    uint64_t delay_ms;     // Initial delay before the first burst
    uint64_t interval_ms;  // Interval for repeated bursts (0 means no repeat)
    
    sender_t* sender_handle;
} burst_data_t;

sender_strategy_t* create_strategy_oneshot(
    make_packet_init init_func,
    packet_free free_func,
    make_packet_func make_func,
    void* packet_args, // Args for the make_func
    send_packet_func send_func,
    void* send_args // Args for the send_func
);

sender_strategy_t* create_strategy_pps(
    make_packet_init init_func,
    packet_free free_func,
    make_packet_func make_func,
    void* packet_args,
    send_packet_func send_func,
    void* send_args,
    uint32_t pps,
    size_t high_watermark
);

sender_strategy_t* create_strategy_burst(
    make_packet_init init_func,
    packet_free free_func,
    make_packet_func make_func,
    void* packet_args,
    send_packet_func send_func,
    void* send_args,
    uint64_t delay_ms,
    uint64_t interval_ms
);

#endif