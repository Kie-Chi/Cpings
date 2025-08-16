#include "strategy.h"

static void default_start(sender_t* sender, void* strategy_data) {
    default_strategy_data_t* data = (default_strategy_data_t*)strategy_data;
    
    packet_work_t* work = (packet_work_t*)alloc_memory(sizeof(packet_work_t));
    if (!work) {
        fprintf(stderr, "Failed to allocate memory for oneshot work\n");
        return;
    }

    // Just set the handle. The worker will use this to find the strategy.
    work->sender_handle = sender;
    work->batch = NULL;
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
    oneshot_data_t* data = (oneshot_data_t*)strategy_data;
    if (!data) return;

    if (data->default_data.free_packet_args_func && data->default_data.packet_args) {
        data->default_data.free_packet_args_func(data->default_data.packet_args);
    }

    if (strategy_data) {
        free(strategy_data);
    }
}

sender_strategy_t* create_strategy_oneshot(
    make_packet_func make_func,
    void* packet_args,
    free_func free_packet_args_func,
    send_packet_func send_func,
    void* send_args,
    free_func free_send_args_func
) {
    sender_strategy_t* strategy = (sender_strategy_t*)alloc_memory(sizeof(sender_strategy_t));
    oneshot_data_t* data = (oneshot_data_t*)alloc_memory(sizeof(oneshot_data_t));

    // Populate data
    data->default_data.make_func = make_func;
    data->default_data.packet_args = packet_args;
    data->default_data.free_packet_args_func = free_packet_args_func;
    data->default_data.build_cb = default_build_work_cb;
    data->default_data.after_build_cb = default_after_work_cb;

    strategy->data = data;
    strategy->start = default_start;
    strategy->stop = oneshot_stop;
    strategy->free_data = oneshot_free_data;
    strategy->send_func = send_func ? send_func : default_send;
    strategy->send_args = send_args;
    strategy->free_send_args_func = free_send_args_func;
    
    return strategy;
}


/*
    PPS
*/

static void pps_after_build_cb(uv_work_t* req, int status) {
    packet_work_t* work = (packet_work_t*)req;
    sender_t* sender = work->sender_handle;
    pps_data_t* pps_data = (pps_data_t*)sender->strategy->data;

    // Add the completed batch to our private queue if it was successful.
    if (status != UV_ECANCELED && work->batch && work->batch->packets.head) {
        pthread_mutex_lock(&pps_data->buffer_mutex);
        
        if (pps_data->private_batch_queue->tail) {
            pps_data->private_batch_queue->tail->next = work->batch;
        } else {
            pps_data->private_batch_queue->head = work->batch;
        }
        pps_data->private_batch_queue->tail = work->batch;
        pps_data->private_queue_size++;

        pthread_mutex_unlock(&pps_data->buffer_mutex);
    } else if (work->batch) {
        // Cleanup failed or empty batch
        arena_free(&work->batch->arena);
        free(work->batch);
    }

    pthread_mutex_lock(&pps_data->buffer_mutex);
    pps_data->active_batches--;
#ifdef _DEBUG
    printf("[PPS] Producer finished. Batches in queue: %zu, Active batches: %zu\n", pps_data->private_queue_size, pps_data->active_batches);
#endif
    pthread_mutex_unlock(&pps_data->buffer_mutex);
    
    free(work);
}

static void pps_timer_cb(uv_timer_t* handle) {
    pps_data_t* data = (pps_data_t*)handle->data;
    sender_t* sender = data->sender_handle;

    if (!sender->is_running) return;

    packet_batch_t* batch_to_send = NULL;
    pthread_mutex_lock(&data->buffer_mutex);
    if (data->private_batch_queue->head) {
        batch_to_send = data->private_batch_queue->head;
        data->private_batch_queue->head = batch_to_send->next;
        if (data->private_batch_queue->head == NULL) {
            data->private_batch_queue->tail = NULL;
        }
        batch_to_send->next = NULL;
        data->private_queue_size--;
    }
    pthread_mutex_unlock(&data->buffer_mutex);

    if (batch_to_send) {
        sender_add_batch_to_queue(sender, batch_to_send);
    }

    size_t producers_to_launch = 0;
    pthread_mutex_lock(&data->buffer_mutex);
    
    size_t current_supply = data->private_queue_size + data->active_batches;
    if (current_supply < data->high_watermark) {
        size_t deficit = data->high_watermark - current_supply;
        size_t available_slots = data->max_concurrent_batches - data->active_batches;
        producers_to_launch = MIN(deficit, available_slots);
        if (producers_to_launch > 0) {
            data->active_batches += producers_to_launch;
        }
    }
    
    pthread_mutex_unlock(&data->buffer_mutex);

    if (producers_to_launch > 0) {
#ifdef _DEBUG
        printf("[PPS] Buffer low. Launching %zu new producer(s).\n", producers_to_launch);
#endif
        for (size_t i = 0; i < producers_to_launch; i++) {
            packet_work_t* work = (packet_work_t*)alloc_memory(sizeof(packet_work_t));
            memset(work, 0, sizeof(packet_work_t));
            work->sender_handle = data->sender_handle;
            
            uv_queue_work(sender->loop, &work->work_req, 
                          data->default_data.build_cb,
                          pps_after_build_cb);
        }
    }
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

    if (data->default_data.free_packet_args_func && data->default_data.packet_args) {
        data->default_data.free_packet_args_func(data->default_data.packet_args);
    }

    pthread_mutex_destroy(&data->buffer_mutex);
    if (data->private_batch_queue) {
        free_batch_queue(data->private_batch_queue);
        data->private_batch_queue = NULL;
    }
    free(data);
}

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
) {
    sender_strategy_t* strategy = (sender_strategy_t*)alloc_memory(sizeof(sender_strategy_t));
    pps_data_t* data = (pps_data_t*)alloc_memory(sizeof(pps_data_t));
    
    if (packet_args != NULL && (make_func == pps_make || make_func == NULL)) {
        pps_make_args_t* pps_args = (pps_make_args_t*)packet_args;
        double interval_sec = PPS_TIMER_INTERVAL_MS / 1000.0;
        uint32_t calculated_count = (uint32_t)(pps * interval_sec);
        if (pps > 0 && calculated_count < 1) {
            calculated_count = 1;
        }
        
        if (pps_args->count != calculated_count) {
#ifdef _DEBUG
            printf("[PPS Strategy Warning] User-provided batch count (%u) is suboptimal for the target PPS (%u).\n", pps_args->count, pps);
            printf("[PPS Strategy Info] Forcing batch count to the calculated optimal value: %u\n", calculated_count);
#endif
            pps_args->count = calculated_count;
        } else {
#ifdef _DEBUG
            printf("[PPS Strategy Info] Using user-provided batch count: %u, which matches the calculated optimal value.\n", pps_args->count);
#endif
        }
    }

    data->pps = pps;
    data->high_watermark = high_watermark;
    data->max_concurrent_batches = (max_concurrent_batches > 0) ? max_concurrent_batches : 4; // Ensure at least 1 batch can be processed
    data->active_batches = 0;
    data->private_queue_size = 0;
    pthread_mutex_init(&data->buffer_mutex, NULL);

    // Initialize the private queue of batches
    data->private_batch_queue = (sender_queue_t*)alloc_memory(sizeof(sender_queue_t));
    data->private_batch_queue->head = NULL;
    data->private_batch_queue->tail = NULL;

    data->default_data.make_func = make_func;
    data->default_data.packet_args = packet_args;
    data->default_data.free_packet_args_func = free_packet_args_func;
    data->default_data.build_cb = default_build_work_cb; 
    data->default_data.after_build_cb = pps_after_build_cb; // This is important

    strategy->data = data;
    strategy->start = pps_start;
    strategy->stop = pps_stop;
    strategy->free_data = pps_free_data;
    strategy->send_func = send_func ? send_func : default_send;
    strategy->send_args = send_args;
    strategy->free_send_args_func = free_send_args_func;

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
    packet_work_t* work = (packet_work_t*)alloc_memory(sizeof(packet_work_t));
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
    burst_data_t* data = (burst_data_t*)strategy_data;
    if (!data) return;

    if (data->default_data.free_packet_args_func && data->default_data.packet_args) {
        data->default_data.free_packet_args_func(data->default_data.packet_args);
    }

    if (strategy_data) {
        free(strategy_data);
    }
}

sender_strategy_t *create_strategy_burst(
    make_packet_func make_func,
    void *packet_args,
    free_func free_packet_args_func,
    send_packet_func send_func,
    void *send_args,
    free_func free_send_args_func,
    uint64_t delay_ms,
    uint64_t interval_ms)
{
    sender_strategy_t *strategy = (sender_strategy_t *)alloc_memory(sizeof(sender_strategy_t));
    burst_data_t *data = (burst_data_t *)alloc_memory(sizeof(burst_data_t));

    data->default_data.make_func = make_func;
    data->default_data.packet_args = packet_args;
    data->default_data.free_packet_args_func = free_packet_args_func;
    data->default_data.build_cb = default_build_work_cb;
    data->default_data.after_build_cb = default_after_work_cb;

    data->delay_ms = delay_ms;
    data->interval_ms = interval_ms;
    data->sender_handle = NULL;

    strategy->data = data;
    strategy->start = burst_start;
    strategy->stop = burst_stop;
    strategy->free_data = burst_free_data;
    strategy->send_func = send_func ? send_func : default_send;
    strategy->send_args = send_args;
    strategy->free_send_args_func = free_send_args_func;

    return strategy;
}

/*
    Multi-Task 
*/

static void multitask_after_work_cb(uv_work_t* req, int status) {
    packet_work_t* p_work = (packet_work_t*)req;
    multitask_work_t* work = container_of(p_work, multitask_work_t, work);
    
    sender_t* sender = work->work.sender_handle;
    multitask_data_t* data = (multitask_data_t*)sender->strategy->data;

    if (status != UV_ECANCELED && work->work.error_code == NOERROR && work->work.batch) {
        sender_add_batch_to_queue(sender, work->work.batch);
    } else if (work->work.batch) {
        // Cleanup failed or empty batch
        arena_free(&work->work.batch->arena);
        free(work->work.batch);
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
#ifdef _DEBUG
        printf("multitask_aw_cb: all tasks completed, entering wait state\n");
#endif
    }
    pthread_mutex_unlock(&data->queue_mutex);
}


static void multitask_build_work_cb(uv_work_t* req) {
    packet_work_t* p_work = (packet_work_t*)req;
    multitask_work_t* work = container_of(p_work, multitask_work_t, work);
    
    work->work.error_code = NOERROR;
    
    // Create and initialize the batch
    work->work.batch = (packet_batch_t*)alloc_memory(sizeof(packet_batch_t));
    if (!work->work.batch) {
        work->work.error_code = INIT_ERROR;
        return;
    }
    memset(&work->work.batch->arena, 0, sizeof(Arena));
    work->work.batch->packets.head = NULL;
    work->work.batch->packets.tail = NULL;
    
    // Call the user-provided make function with the new arena
    if (!work->make_func(&work->work.batch->arena, &work->work.batch->packets, work->make_args)) {
        work->work.error_code = MAKE_ERROR;
        arena_free(&work->work.batch->arena);
        free(work->work.batch);
        work->work.batch = NULL;
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

    if (data->default_data.free_packet_args_func && data->default_data.packet_args) {
        data->default_data.free_packet_args_func(data->default_data.packet_args);
    }

    multitask_stop(NULL, data);
    pthread_mutex_destroy(&data->queue_mutex);
    pthread_cond_destroy(&data->queue_not_full_cond);
    free(data);
}

sender_strategy_t* create_strategy_multitask(
    send_packet_func send_func,
    void* send_args,
    free_func free_send_args_func,
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

    data->default_data.make_func = NULL; // No default make function

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

