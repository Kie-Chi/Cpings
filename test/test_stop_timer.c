
#include "sender.h"
#include "strategy.h"
#include "common.h"
#include "dns.h"

typedef struct {
    int check_count;
    int max_checks;
} stop_state_t;

/**
 * @brief 停止条件检查函数 (stop_func)
 * 
 * @param state 指向 stop_state_t 结构体的指针
 * @return bool 如果返回 true，sender 将停止；否则继续运行
 */
bool should_stop(void* state) {
    stop_state_t* s = (stop_state_t*)state;
    s->check_count++;

    printf("[Stop Check] Check #%d of %d...\n", s->check_count, s->max_checks);

    if (s->check_count >= s->max_checks) {
        printf("[Stop Check] Condition met! Requesting sender to stop.\n");
        return true; // 返回 true，触发停止流程
    }

    return false; // 返回 false，继续运行
}

/**
 * @brief 状态数据释放函数 (free_func)
 * 
 * @param data 指向由 sender_set_stop_cond 设置的 state 指针
 */
void free_stop_state(void* data) {
    if (data) {
        printf("[Cleanup] Stop condition state freed.\n");
        free(data);
    }
}

int main(int argc, char **argv) {
    // 1. 初始化 libuv 事件循环和 dns 功能
    uv_loop_t *loop = uv_default_loop();
    dns_init();

    // 2. 初始化 sender
    sender_t sender;
    if (sender_init(&sender, loop, "127.0.0.1", 53) != 0) {
        fprintf(stderr, "Failed to initialize sender\n");
        return 1;
    }
    printf("Sender initialized.\n");

    pps_make_args_t make_args = {
        .default_args = {
            .src_ip = "127.0.0.1",
            .dst_ip = "127.0.0.1",
            .src_port = 53,
            .dst_port = 12345,
            .domain_name = "example.com"
        },
        .count = 300 // 每次后台任务生成1000个包
    };

    // 4. 创建 PPS 策略
    sender_strategy_t* pps_strategy = create_strategy_pps(
        default_init,
        default_free,
        pps_make,
        &make_args,
        default_send,
        NULL,
        100,      // 发送速率: 100 pps
        500      // 缓冲区高水位线
    );
    if (!pps_strategy) {
        fprintf(stderr, "Failed to create PPS strategy\n");
        sender_free(&sender);
        return 1;
    }

    // 5. 为 sender 设置策略
    sender_set_strategy(&sender, pps_strategy);
    printf("PPS strategy set.\n");

    
    // 分配并初始化状态数据
    stop_state_t* state = (stop_state_t*)malloc(sizeof(stop_state_t));
    state->check_count = 0;
    state->max_checks = 10; // 检查10次后退出

    uint64_t check_interval_ms = 1000; // 每1000毫秒（1秒）检查一次

    if (sender_set_stop_cond(&sender, should_stop, state, free_stop_state, check_interval_ms) != NOERROR) {
        fprintf(stderr, "Failed to set stop condition\n");
        free(state); // 手动清理
        sender_free(&sender);
        return 1;
    }
    printf("Stop condition set: will stop after %d checks (approx. %d seconds).\n", state->max_checks, (int)(state->max_checks * check_interval_ms / 1000));


    // 7. 启动 sender
    sender_start(&sender);
    printf("Sender started.\n");

    // 8. 运行事件循环
    printf("Running event loop...\n");
    uv_run(loop, UV_RUN_DEFAULT);
    printf("Event loop finished.\n");

    // 9. 清理资源
    // sender_free 会负责停止 timer、调用 free_stop_state 和释放策略
    sender_free(&sender);
    printf("Sender freed.\n");

    // 清理 libuv 循环
    uv_loop_close(loop);
    
    printf("Test finished successfully.\n");
    return 0;
}