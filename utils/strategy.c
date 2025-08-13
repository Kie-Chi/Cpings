#include "strategy.h"

static void oneshot_start(sender_t* sender, void* strategy_data) {
    oneshot_data_t* data = (oneshot_data_t*)strategy_data;
    packet_work_t* work = (packet_work_t*)malloc(sizeof(packet_work_t));
    if (!work) {
        fprintf(stderr, "Failed to allocate memory for oneshot work\n");
        return;
    }

    work->sender_handle = sender;
    work->init_func = data->init_func;
    work->make_func = data->make_func;
    work->free_func = data->free_func;
    work->packet_args = data->packet_args;
    work->queue = NULL;
    work->error_code = NOERROR;
    uv_queue_work(sender->loop, &work->work_req, build_work_cb, send_after_work_cb);
}


static void oneshot_stop(sender_t* sender, void* strategy_data) {
    // No-op
    (void)sender;
    (void)strategy_data;
}

static void oneshot_free_data(void* strategy_data) {
    if (strategy_data) {
        free(strategy_data);
    }
}

sender_strategy_s *create_strategy_oneshot(
    make_packet_init init_func,
    packet_free free_func,
    make_packet_func make_func,
    void* packet_args,
    send_packet_func send_func,
    void* send_args
)
{
    // 1. Allocate the strategy object
    sender_strategy_s* strategy = (sender_strategy_s*)malloc(sizeof(sender_strategy_s));
    if (!strategy) return NULL;

    // 2. Allocate the strategy-specific data
    oneshot_data_t* data = (oneshot_data_t*)malloc(sizeof(oneshot_data_t));
    if (!data) {
        free(strategy);
        return NULL;
    }

    // 3. Populate the data
    data->init_func = init_func ? init_func : default_init;
    data->make_func = make_func;
    data->free_func = free_func ? free_func : default_free;
    data->packet_args = packet_args;

    strategy->data = data;
    strategy->start = oneshot_start;
    strategy->stop = oneshot_stop;
    strategy->free_data = oneshot_free_data;
    strategy->send_func = send_func ? send_func : default_send;
    strategy->send_args = send_args;
    return strategy;
}