#include "sender.h"
#include "strategy.h"
#include "dns.h"
#include "util.h" // for _strdup

#define MAX_QUEUE_CAPACITY 3
#define NUM_WORKER_THREADS 5 

typedef struct {
    int thread_id;
    sender_t* sender;
} worker_args_t;

typedef pps_make_args_t task_args_t;

static void free_task_args(void* args) {
    if (!args) return;
    task_args_t* task_args = (task_args_t*)args;
    free(task_args->default_args.src_ip);
    free(task_args->default_args.dst_ip);
    free(task_args->default_args.domain_name);
    free(task_args);
}

void* worker_thread_func(void* arg) {
    worker_args_t* w_args = (worker_args_t*)arg;
    int tid = w_args->thread_id;
    sender_t* sender = w_args->sender;

    printf("[Worker %d] Started. Will submit tasks rapidly.\n", tid);

    for (int i = 0; i < 5; ++i) { 
        task_args_t* task = malloc(sizeof(task_args_t));
        char domain_buf[32];
        snprintf(domain_buf, sizeof(domain_buf), "task-%d-from-worker-%d.com", i, tid);
        
        task->default_args.src_ip = _strdup("192.168.3.148");
        task->default_args.dst_ip = _strdup("192.168.3.144");
        task->default_args.domain_name = _strdup(domain_buf);
        task->default_args.src_port = 53;
        task->default_args.dst_port = 12345;
        task->count = 10; 

        printf("[Worker %d] Attempting to submit task %d...\n", tid, i);
        multitask_submit_work(sender, pps_make, task, free_task_args);
        printf("[Worker %d] Successfully submitted task %d.\n", tid, i);
        
        usleep(100 * 1000);
    }

    printf("[Worker %d] Finished submitting all tasks.\n", tid);
    free(w_args);
    return NULL;
}

static void on_signal(uv_signal_t* handle, int signum) {
    sender_t* sender = (sender_t*)handle->data;
    printf("\n[Signal] Caught signal %d, requesting sender stop...\n", signum);
    uv_async_send(sender->stop_async);
    uv_signal_stop(handle);
}


int main(int argc, char** argv) {
    srand(time(NULL));
    dns_init();
    uv_loop_t* loop = uv_default_loop();

    sender_t my_sender;
    if (sender_init(&my_sender, loop, "192.168.3.144", 53) != 0) {
        fprintf(stderr, "Failed to initialize sender\n");
        return 1;
    }
    printf("[+] Sender initialized.\n");

    printf("[*] Creating Multi-Task strategy with a bounded queue of size %d.\n", MAX_QUEUE_CAPACITY);
    sender_strategy_t* strategy = create_strategy_multitask(NULL, NULL, MAX_QUEUE_CAPACITY);
    if (!strategy) {
        fprintf(stderr, "Failed to create multi-task strategy\n");
        sender_free(&my_sender);
        return 1;
    }
    sender_set_strategy(&my_sender, strategy);
    printf("[+] Multi-Task strategy created and set.\n");

    // 3. 设置信号处理器
    uv_signal_t signal_handle;
    uv_signal_init(loop, &signal_handle);
    signal_handle.data = &my_sender;
    uv_signal_start(&signal_handle, on_signal, SIGINT);

    // 4. 启动 sender，使其进入运行状态
    printf("[*] Starting sender...\n");
    sender_start(&my_sender);
    
    // 5. 创建并启动多个工作线程
    pthread_t workers[NUM_WORKER_THREADS];
    for (int i = 0; i < NUM_WORKER_THREADS; ++i) {
        worker_args_t* args = malloc(sizeof(worker_args_t));
        args->thread_id = i + 1;
        args->sender = &my_sender;
        if (pthread_create(&workers[i], NULL, worker_thread_func, args) != 0) {
            perror("pthread_create");
            // 在实际项目中需要更完善的错误处理和资源回收
        }
    }
    printf("[*] %d worker threads have been launched to submit tasks.\n", NUM_WORKER_THREADS);

    // 6. 运行事件循环
    printf("[*] Event loop is running... Observe the logs for backpressure. Press Ctrl+C to exit.\n");
    uv_run(loop, UV_RUN_DEFAULT);

    // 7. 清理资源
    printf("\n[*] Event loop has stopped, cleaning up resources...\n");

    // 等待所有工作线程结束
    printf("[*] Waiting for all worker threads to complete...\n");
    for (int i = 0; i < NUM_WORKER_THREADS; ++i) {
        pthread_join(workers[i], NULL);
    }
    printf("[*] All worker threads have completed.\n");
    
    sender_free(&my_sender);
    
    uv_run(loop, UV_RUN_ONCE);
    uv_loop_close(loop);

    printf("[*] Test finished.\n");
    return 0;
}