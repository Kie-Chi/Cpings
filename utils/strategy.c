#include "strategy.h"

static void default_start(sender_t* sender, void* strategy_data) {
    default_strategy_data_t* data = (default_strategy_data_t*)strategy_data;
    
    packet_work_t* work = (packet_work_t*)malloc(sizeof(packet_work_t));
    if (!work) {
        fprintf(stderr, "Failed to allocate memory for oneshot work\n");
        return;
    }

    // Just set the handle. The worker will use this to find the strategy.
    work->sender_handle = sender;
    work->queue = NULL;
    work->error_code = NOERROR;
    
    // Queue the work request.
    uv_queue_work(sender->loop, &work->work_req, data->build_cb, data->after_build_cb);
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

sender_strategy_t* create_strategy_oneshot(
    make_packet_init init_func,
    packet_free free_func,
    make_packet_func make_func,
    void* packet_args,
    send_packet_func send_func,
    void* send_args
)
{
    // 1. Allocate the strategy object
    sender_strategy_t* strategy = (sender_strategy_t*)malloc(sizeof(sender_strategy_t));
    if (!strategy) return NULL;

    // 2. Allocate the strategy-specific data
    oneshot_data_t* data = (oneshot_data_t*)malloc(sizeof(oneshot_data_t));
    if (!data) {
        free(strategy);
        return NULL;
    }

    // 3. Populate the data
    data->default_data.init_func = init_func ? init_func : default_init;
    data->default_data.make_func = make_func;
    data->default_data.free_func = free_func ? free_func : default_free;
    data->default_data.packet_args = packet_args;
    data->default_data.build_cb = default_build_work_cb;
    data->default_data.after_build_cb = default_after_work_cb;

    strategy->data = data;
    strategy->start = default_start;
    strategy->stop = oneshot_stop;
    strategy->free_data = oneshot_free_data;
    strategy->send_func = send_func ? send_func : default_send;
    strategy->send_args = send_args;
    return strategy;
}

/*
    PPS
*/

static void pps_after_build_cb(uv_work_t* req, int status) {
    packet_work_t* work = (packet_work_t*)req;
    pps_data_t* pps_data = (pps_data_t*)work->sender_handle->strategy->data;

    if (status == UV_ECANCELED) {
        if (work->queue) pps_data->default_data.free_func(work->queue);
        free(work);
        return;
    }
    if (work->queue && work->queue->head) {
        pthread_mutex_lock(&pps_data->buffer_mutex);
        
        packet_t* new_head = work->queue->head;
        packet_t* new_tail = work->queue->tail;
        size_t count = 0;
        for (packet_t* p = new_head; p; p = p->next) count++;

        if (pps_data->private_queue->tail) {
            pps_data->private_queue->tail->next = new_head;
        } else {
            pps_data->private_queue->head = new_head;
        }
        pps_data->private_queue->tail = new_tail;
        pps_data->private_queue_size += count;

        pthread_mutex_unlock(&pps_data->buffer_mutex);

        printf("[PPS] Producer finished. Added %zu packets to buffer (new size: %zu).\n", count, pps_data->private_queue_size);
    }
    
    pps_data->producing = false;
    free(work->queue);
    free(work);
}

static void pps_timer_cb(uv_timer_t* handle) {
    pps_data_t* data = (pps_data_t*)handle->data;
    sender_t* sender = data->sender_handle;

    // If sender has been stopped, do nothing.
    if (!sender->is_running) return;

    // 1. Move packets from private buffer to sender's public queue
    uint32_t packets_to_move = (data->pps * PPS_TIMER_INTERVAL_MS) / 1000;
    if (packets_to_move == 0 && data->pps > 0) packets_to_move = 1;

    if (packets_to_move > 0) {
        packet_queue_t batch_to_send = { .head = NULL, .tail = NULL };
        size_t moved_count = 0;

        pthread_mutex_lock(&data->buffer_mutex);
        if (data->private_queue_size > 0) {
            batch_to_send.head = data->private_queue->head;
            packet_t* current = data->private_queue->head;
            while(moved_count < packets_to_move && current && current->next) {
                current = current->next;
                moved_count++;
            }
            // If we moved any packets, split the list
            batch_to_send.tail = current;
            data->private_queue->head = current->next;
            if (data->private_queue->head == NULL) {
                data->private_queue->tail = NULL;
            }
            batch_to_send.tail->next = NULL; // Terminate the batch list
            data->private_queue_size -= (moved_count + 1);
        }
        pthread_mutex_unlock(&data->buffer_mutex);

        if (batch_to_send.head) {
            sender_add_to_queue(data->sender_handle, &batch_to_send);
        }
    }

    // 2. Check if we need to produce more packets
    pthread_mutex_lock(&data->buffer_mutex);
    if (!data->producing && data->private_queue_size < data->high_watermark) {
        data->producing = true;
        
        printf("[PPS] Buffer low (size: %zu). Dispatching new producer task.\n", data->private_queue_size);

        packet_work_t* work = (packet_work_t*)malloc(sizeof(packet_work_t));
        memset(work, 0, sizeof(packet_work_t));
        work->sender_handle = data->sender_handle;
        
        uv_queue_work(data->sender_handle->loop, &work->work_req, 
                      data->default_data.build_cb,
                      data->default_data.after_build_cb);
    }
    pthread_mutex_unlock(&data->buffer_mutex);
}

static void pps_start(sender_t* sender, void* strategy_data) {
    pps_data_t* data = (pps_data_t*)strategy_data;
    data->sender_handle = sender;
    uv_timer_init(sender->loop, &data->pps_timer);
    data->pps_timer.data = data;
    uv_timer_start(&data->pps_timer, pps_timer_cb, 0, PPS_TIMER_INTERVAL_MS);
}

static void pps_stop(sender_t* sender, void* strategy_data) {
    (void)sender;
    pps_data_t* data = (pps_data_t*)strategy_data;
    // Check if handle is active and not closing before stopping
    if (uv_is_active((uv_handle_t*)&data->pps_timer)) {
        uv_timer_stop(&data->pps_timer);
    }
}

static void pps_free_data(void* strategy_data) {
    pps_data_t* data = (pps_data_t*)strategy_data;
    if (!data) return;

    pthread_mutex_destroy(&data->buffer_mutex);
    if (data->private_queue) {
        data->default_data.free_func(data->private_queue);
    }
    free(data);
}

sender_strategy_t* create_strategy_pps(
    make_packet_init init_func, packet_free free_func, make_packet_func make_func,
    void* packet_args, send_packet_func send_func, void* send_args,
    uint32_t pps, size_t high_watermark
) {
    sender_strategy_t* strategy = (sender_strategy_t*)malloc(sizeof(sender_strategy_t));
    if (!strategy) return NULL;

    pps_data_t* data = (pps_data_t*)malloc(sizeof(pps_data_t));
    if (!data) {
        free(strategy);
        return NULL;
    }
    
    // --- Initialize PPS specific fields ---
    data->pps = pps;
    data->high_watermark = high_watermark;
    data->producing = false;
    data->private_queue_size = 0;
    data->sender_handle = NULL; // Will be set on start
    pthread_mutex_init(&data->buffer_mutex, NULL);
    data->private_queue = malloc(sizeof(packet_queue_t));
    if (!data->private_queue) {
        pthread_mutex_destroy(&data->buffer_mutex);
        free(data);
        free(strategy);
        return NULL;
    }
    data->private_queue->head = NULL;
    data->private_queue->tail = NULL;


    // --- Populate common fields ---
    data->default_data.init_func = init_func ? init_func : default_init;
    data->default_data.free_func = free_func ? free_func : default_free;
    data->default_data.make_func = make_func;
    data->default_data.packet_args = packet_args;
    data->default_data.build_cb = default_build_work_cb; 
    data->default_data.after_build_cb = pps_after_build_cb; 

    // --- Populate strategy function pointers ---
    strategy->data = data;
    strategy->start = pps_start;
    strategy->stop = pps_stop;
    strategy->free_data = pps_free_data;
    strategy->send_func = send_func ? send_func : default_send;
    strategy->send_args = send_args;

    return strategy;
}

/*
    Burst
*/

static void burst_timer_cb(uv_timer_t* handle) {
    burst_data_t* data = (burst_data_t*)handle->data;
    sender_t* sender = data->sender_handle;

    if (!sender->is_running) {
        return;
    }
    
    printf("[BURST] Timer fired! Triggering packet generation task.\n");
    packet_work_t* work = (packet_work_t*)malloc(sizeof(packet_work_t));
    if (!work) {
        fprintf(stderr, "Failed to allocate memory for burst work\n");
        return;
    }
    memset(work, 0, sizeof(packet_work_t));
    work->sender_handle = sender;
    uv_queue_work(sender->loop, &work->work_req, 
                  data->default_data.build_cb, 
                  data->default_data.after_build_cb);
}

static void burst_start(sender_t* sender, void* strategy_data) {
    burst_data_t* data = (burst_data_t*)strategy_data;
    data->sender_handle = sender; // Store sender handle

    uv_timer_init(sender->loop, &data->burst_timer);
    data->burst_timer.data = data; // Link timer back to our data

    uv_timer_start(&data->burst_timer, burst_timer_cb, data->delay_ms, data->interval_ms);
}

static void burst_stop(sender_t* sender, void* strategy_data) {
    (void)sender;
    burst_data_t* data = (burst_data_t*)strategy_data;
    if (uv_is_active((uv_handle_t*)&data->burst_timer)) {
        uv_timer_stop(&data->burst_timer);
    }
}

static void burst_free_data(void* strategy_data) {
    if (strategy_data) {
        free(strategy_data);
    }
}

sender_strategy_t* create_strategy_burst(
    make_packet_init init_func,
    packet_free free_func,
    make_packet_func make_func,
    void* packet_args,
    send_packet_func send_func,
    void* send_args,
    uint64_t delay_ms,
    uint64_t interval_ms
) {
    sender_strategy_t* strategy = (sender_strategy_t*)malloc(sizeof(sender_strategy_t));
    if (!strategy) return NULL;

    burst_data_t* data = (burst_data_t*)malloc(sizeof(burst_data_t));
    if (!data) {
        free(strategy);
        return NULL;
    }

    // --- Populate common fields ---
    data->default_data.init_func = init_func ? init_func : default_init;
    data->default_data.free_func = free_func ? free_func : default_free;
    data->default_data.make_func = make_func;
    data->default_data.packet_args = packet_args;
    data->default_data.build_cb = default_build_work_cb;
    data->default_data.after_build_cb = default_after_work_cb;

    // --- Populate burst-specific fields ---
    data->delay_ms = delay_ms;
    data->interval_ms = interval_ms;
    data->sender_handle = NULL; // Will be set on start

    // --- Populate strategy function pointers ---
    strategy->data = data;
    strategy->start = burst_start;
    strategy->stop = burst_stop;
    strategy->free_data = burst_free_data;
    strategy->send_func = send_func ? send_func : default_send;
    strategy->send_args = send_args;

    return strategy;
}

/*
    Multi-Task 
*/

static void multitask_after_work_cb(uv_work_t* req, int status) {
    // Robust but seems no-use
    packet_work_t* p_work = (packet_work_t*)req;
    multitask_work_t* work = container_of(p_work, multitask_work_t, work);
    
    sender_t* sender = work->work.sender_handle;
    multitask_data_t* data = (multitask_data_t*)sender->strategy->data;

    if (status != UV_ECANCELED && work->work.error_code == NOERROR && work->work.queue) {
#ifdef _DEBUG
        printf("multitask_aw_cb: generate packets successfully, sent to queue\n");
#endif
        sender_add_to_queue(sender, work->work.queue);
        free(work->work.queue); 
    } else if (work->work.error_code != NOERROR) {
#ifdef _DEBUG
        fprintf(stderr, "multitask_aw_cb: error when generate packets, for %d\n", work->work.error_code);
#endif
        if (work->work.queue) default_free(work->work.queue);
    }

    if (work->free_args_func && work->make_args) {
        work->free_args_func(work->make_args);
    }
    free(work);

    pthread_mutex_lock(&data->queue_mutex);
    data->is_working = false;
    if (data->queue_head != NULL) {
#ifdef _DEBUG
        printf("multitask_aw_cb: there are more tasks in the queue, triggering scheduler\n");
#endif
        uv_async_send(&data->work_trigger_async);
    } else {
#ifdef _DBUEG
        printf("multitask_aw_cb: all tasks completed, entering wait state\n");
#endif
    }
    pthread_mutex_unlock(&data->queue_mutex);
}


static void multitask_build_work_cb(uv_work_t* req) {
    packet_work_t* p_work = (packet_work_t*)req;
    multitask_work_t* work = container_of(p_work, multitask_work_t, work);
    
    work->work.error_code = NOERROR;
    work->work.queue = NULL;

    if (!default_init(&work->work.queue)) {
        work->work.error_code = INIT_ERROR;
        return;
    }
    if (!work->make_func(work->work.queue, work->make_args)) {
        work->work.error_code = MAKE_ERROR;
        default_free(work->work.queue);
        work->work.queue = NULL;
        return;
    }
}

static void multitask_async_cb(uv_async_t* handle) {
    multitask_data_t* data = (multitask_data_t*)handle->data;
    
    pthread_mutex_lock(&data->queue_mutex);
    
    if (data->is_working || data->queue_head == NULL) {
        pthread_mutex_unlock(&data->queue_mutex);
        return;
    }

    data->is_working = true;
    multitask_work_t* work_to_do = data->queue_head;
    data->queue_head = data->queue_head->next;
    if (data->queue_head == NULL) {
        data->queue_tail = NULL;
    }
    data->current_queue_size--;

    if (data->max_queue_size > 0 && data->current_queue_size == data->max_queue_size - 1) {
#ifdef _DEBUG
        printf("multitask_bw_cb: Queue is no longer full. Signaling a waiting submitter.\n");
#endif 
        pthread_cond_signal(&data->queue_not_full_cond);
    }
    
    pthread_mutex_unlock(&data->queue_mutex);

    work_to_do->work.sender_handle = data->sender_handle;
    uv_queue_work(data->sender_handle->loop, &work_to_do->work.work_req,
                  multitask_build_work_cb,
                  multitask_after_work_cb);
}

static void multitask_start(sender_t* sender, void* strategy_data) {
    multitask_data_t* data = (multitask_data_t*)strategy_data;
    data->sender_handle = sender;
}

static void multitask_stop(sender_t* sender, void* strategy_data) {
    multitask_data_t* data = (multitask_data_t*)strategy_data;
    if (uv_is_active((uv_handle_t*)&data->work_trigger_async)) {
        uv_close((uv_handle_t*)&data->work_trigger_async, NULL);
    }
    
    pthread_mutex_lock(&data->queue_mutex);
    multitask_work_t* current = data->queue_head;
    while(current) {
        multitask_work_t* next = current->next;
        if (current->free_args_func && current->make_args) {
            current->free_args_func(current->make_args);
        }
        free(current);
        current = next;
    }
    data->queue_head = NULL;
    data->queue_tail = NULL;
    pthread_mutex_unlock(&data->queue_mutex);
}

static void multitask_free_data(void* strategy_data) {
    multitask_data_t* data = (multitask_data_t*)strategy_data;
    if (!data) return;
    multitask_stop(NULL, data);
    pthread_mutex_destroy(&data->queue_mutex);
    pthread_cond_destroy(&data->queue_not_full_cond);
    free(data);
}

sender_strategy_t* create_strategy_multitask(
    send_packet_func send_func,
    void* send_args,
    size_t max_queue_size
) {
    sender_strategy_t* strategy = (sender_strategy_t*)alloc_memory(sizeof(sender_strategy_t));
    if (!strategy) return NULL;

    multitask_data_t* data = (multitask_data_t*)alloc_memory(sizeof(multitask_data_t));
    if (!data) {
        free(strategy);
        return NULL;
    }
    
    pthread_mutex_init(&data->queue_mutex, NULL);

    pthread_cond_init(&data->queue_not_full_cond, NULL);
    data->max_queue_size = max_queue_size;
    data->current_queue_size = 0;

    data->is_working = false;

    strategy->data = data;
    strategy->start = multitask_start;
    strategy->stop = multitask_stop;
    strategy->free_data = multitask_free_data;
    strategy->send_func = send_func ? send_func : default_send;
    strategy->send_args = send_args;

    data->default_data.init_func = default_init;
    data->default_data.free_func = default_free;

    return strategy;
}

int multitask_submit_work(
    sender_t* sender,
    make_packet_func make_func,
    void* make_args,
    void (*free_args_func)(void*)
) {
    if (!sender || !sender->strategy || sender->strategy->start != multitask_start) {
        fprintf(stderr, "fail to submit work");
#ifdef _DEBUG
        if (!sender) {
            fprintf(stderr, ", for no sender\n");
        }
        if (!sender->strategy) {
            fprintf(stderr, ", for no strategy\n");
        }
        if (sender->strategy->start != multitask_start) {
            fprintf(stderr, ", for not multitask strategy\n");
        }
#endif
        return BROKEN_ERROR;
    }
    multitask_data_t* data = (multitask_data_t*)sender->strategy->data;

    multitask_work_t* new_work = (multitask_work_t*)alloc_memory(sizeof(multitask_work_t));
    if (!new_work) {
        fprintf(stderr, "alloc memory error\n");
        return INIT_ERROR;
    }
    new_work->make_func = make_func;
    new_work->make_args = make_args;
    new_work->free_args_func = free_args_func;
    
    pthread_mutex_lock(&data->queue_mutex);
    if (data->max_queue_size > 0) {
        while (data->current_queue_size >= data->max_queue_size) {
#ifdef _DEBUG
            printf("multitask_submit_work: queue is full (size: %zu). Waiting...\n", data->current_queue_size);
#endif
            pthread_cond_wait(&data->queue_not_full_cond, &data->queue_mutex);
        }
    }
    if (data->queue_tail == NULL) {
        data->queue_head = new_work;
        data->queue_tail = new_work;
    } else {
        data->queue_tail->next = new_work;
        data->queue_tail = new_work;
    }
    data->current_queue_size++;
    pthread_mutex_unlock(&data->queue_mutex);

    if (data->work_trigger_async.data == NULL) {
        uv_async_init(sender->loop, &data->work_trigger_async, multitask_async_cb);
        data->work_trigger_async.data = data;
    }
    
#ifdef _DEBUG
    printf("multitask_submit_work: submit a work to do\n");
#endif
    uv_async_send(&data->work_trigger_async);

    return 0;
}

