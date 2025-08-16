// ======== test_multitask_sender.c ========
#include <time.h>    // For srand
#include <stdlib.h>  // For rand
#include "sender.h"
#include "strategy.h"
#include "dns.h"

static void on_signal(uv_signal_t* handle, int signum) {
    sender_t* sender = (sender_t*)handle->data;
    printf("\n[Signal] Caught signal %d, requesting sender stop...\n", signum);
    // Use the sender's built-in async stop mechanism, which will eventually cause uv_run to exit.
    uv_async_send(sender->stop_async);
    uv_signal_stop(handle);
}

typedef pps_make_args_t task_args_t;

static void free_task_args(void* args) {
    if (!args) return;
    task_args_t* task_args = (task_args_t*)args;
    free(task_args->default_args.src_ip);
    free(task_args->default_args.dst_ip);
    free(task_args->default_args.domain_name);

    free(task_args);
}

static void task_submit_timer_cb(uv_timer_t* handle) {
    sender_t* sender = (sender_t*)handle->data;

    // --- Dynamically generate task arguments ---
    task_args_t* args = malloc(sizeof(task_args_t));
    if (!args) {
        fprintf(stderr, "Failed to allocate memory for task arguments\n");
        return;
    }
    
    // Randomize parameters
    char src_ip_buf[16], dst_ip_buf[16], domain_buf[32];
    snprintf(src_ip_buf, sizeof(src_ip_buf), "192.168.3.148");
    snprintf(dst_ip_buf, sizeof(dst_ip_buf), "192.168.3.144");
    snprintf(domain_buf, sizeof(domain_buf), "random-%d.com", rand() % 1000);

    // Use _strdup to allocate memory, as free_task_args will free them later.
    args->default_args.src_ip = _strdup(src_ip_buf);
    args->default_args.dst_ip = _strdup(dst_ip_buf);
    args->default_args.domain_name = _strdup(domain_buf);
    args->default_args.src_port = 53;
    args->default_args.dst_port = 10000 + rand() % 10000;
    args->count = 100; // Generate a random number of packets (500-2000)

    printf("[Timer] Preparing to submit a new task:\n"
           "        Source: %s:%u\n"
           "        Target: %s:%u\n"
           "        Domain: %s\n"
           "        Count: %u packets\n",
           args->default_args.src_ip, args->default_args.src_port,
           args->default_args.dst_ip, args->default_args.dst_port,
           args->default_args.domain_name, args->count);

    multitask_submit_work(sender, pps_make, args, free_task_args);
    
    uint64_t next_interval_ms = 1000 + (rand() % 2001); // 1000ms + (0 to 2000ms)
    printf("[Timer] Next task will be submitted in %llu ms.\n", (unsigned long long)next_interval_ms);
    uv_timer_start(handle, task_submit_timer_cb, next_interval_ms, 0); // 0 = non-repeating
}


int main(int argc, char** argv) {
    // Initialize the random seed
    srand(time(NULL));
    dns_init();

    // 1. Initialize the libuv event loop
    uv_loop_t* loop = uv_default_loop();

    // 2. Initialize the sender
    // For the multitask strategy, the initial IP/Port are not critical, as each task will provide its own.
    sender_t my_sender;
    if (sender_init(&my_sender, loop, "192.168.3.144", 53) != 0) {
        fprintf(stderr, "Failed to initialize sender\n");
        return 1;
    }
    printf("[+] Sender initialized successfully.\n");

    // 3. Create and set the Multi-Task strategy
    // This strategy itself is simple, as it just provides a framework for receiving tasks.
    sender_strategy_t* strategy = create_strategy_multitask(NULL, NULL, NULL, 10);
    if (!strategy) {
        fprintf(stderr, "Failed to create multi-task strategy\n");
        sender_free(&my_sender);
        return 1;
    }
    sender_set_strategy(&my_sender, strategy);
    printf("[+] Multi-Task strategy created and set successfully.\n");

    // 4. Set up the signal handler for graceful shutdown
    uv_signal_t signal_handle;
    uv_signal_init(loop, &signal_handle);
    signal_handle.data = &my_sender; // Link the sender instance to the handle
    uv_signal_start(&signal_handle, on_signal, SIGINT);

    // 5. Create and start a timer to simulate random, incoming external requests
    uv_timer_t submit_timer;
    uv_timer_init(loop, &submit_timer);
    submit_timer.data = &my_sender;

    printf("[*] Starting task submission timer, will submit the first task immediately.\n");
    uv_timer_start(&submit_timer, task_submit_timer_cb, 0, 0); 
    
    // 6. Start the sender, putting it in the is_running state, ready to receive and process tasks.
    printf("[*] Starting sender, putting it into a running/waiting state.\n");
    sender_start(&my_sender);

    // 7. Run the libuv event loop
    printf("[*] Event loop is running... Press Ctrl+C to exit.\n");
    uv_run(loop, UV_RUN_DEFAULT);

    // 8. Clean up resources (code execution continues here after uv_stop is called)
    printf("\n[*] Event loop has stopped, cleaning up resources...\n");
    // Ensure the timer is stopped and can be safely closed
    if (uv_is_active((uv_handle_t*)&submit_timer)) {
        uv_timer_stop(&submit_timer);
    }
    uv_close((uv_handle_t*)&submit_timer, NULL);

    // sender_free will take care of stopping and freeing the strategy
    sender_free(&my_sender); 
    
    // Run the loop one more time to ensure all close callbacks have been executed
    uv_run(loop, UV_RUN_ONCE);
    uv_loop_close(loop);

    printf("[*] Test finished.\n");
    return 0;
}