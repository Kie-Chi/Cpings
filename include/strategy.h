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

    uv_timer_t pps_timer;
    uint32_t pps;
    size_t high_watermark; // Now represents a watermark of BATCHES, not packets.
    size_t max_concurrent_batches; // Maximum number of batches that can be processed concurrently;

    sender_queue_t* private_batch_queue;
    volatile size_t private_queue_size; // Number of batches in the queue.
    volatile size_t active_batches; // Number of batches currently being processed.

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


typedef struct multitask_work_s {
    packet_work_t work;

    make_packet_func make_func;
    void* make_args;
    void (*free_args_func)(void*);

    struct multitask_work_s* next;
} multitask_work_t;

typedef struct multitask_data_s {
    default_strategy_data_t default_data;

    multitask_work_t* queue_head;
    multitask_work_t* queue_tail;
    
    pthread_mutex_t queue_mutex;
    uv_async_t work_trigger_async;
    
    volatile bool is_working;

    pthread_cond_t queue_not_full_cond;
    size_t max_queue_size;
    volatile size_t current_queue_size;

    sender_t* sender_handle;
} multitask_data_t;

/*
    Normal-Type Create Function of Strategy
*/

sender_strategy_t* create_strategy_oneshot(
    make_packet_func make_func,
    void* packet_args, // Args for the make_func
    free_func free_packet_args_func, // Free func for packet_args
    send_packet_func send_func,
    void* send_args, // Args for the send_func
    free_func free_send_args_func // Free func for send_args
);

sender_strategy_t* create_strategy_pps(
    make_packet_func make_func,
    void* packet_args,
    free_func free_packet_args_func,
    send_packet_func send_func,
    void* send_args,
    free_func free_send_args_func,
    uint32_t pps,
    size_t high_watermark,
    size_t max_concurrent_batches
);

sender_strategy_t* create_strategy_burst(
    make_packet_func make_func,
    void* packet_args,
    free_func free_packet_args_func,
    send_packet_func send_func,
    void* send_args,
    free_func free_send_args_func,
    uint64_t delay_ms,
    uint64_t interval_ms
);

/*
    Task-Drive Type Create Function of Strategy
*/

sender_strategy_t* create_strategy_multitask(
    send_packet_func send_func,
    void* send_args,
    free_func free_send_args_func,
    size_t max_queue_size
);

int multitask_submit_work(
    sender_t* sender,
    make_packet_func make_func,
    void* make_args,
    void (*free_args_func)(void*)
);

#endif