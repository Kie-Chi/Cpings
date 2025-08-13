// ======== test_sender.c (New File) ========

#include "sender.h"
#include "strategy.h"

int main(int argc, char** argv) {
    int ch;
    char* target_ip = "192.168.3.144";
    uint16_t target_port = 12345;
    uint16_t src_port = 53;
    char* domain_name = "example.com";
    char* src_ip = "192.168.3.131"; // Spoofed source IP
    // Initialize DNS subsystem for packet creation
    dns_init();

    // 1. Initialize libuv event loop
    uv_loop_t* loop = uv_default_loop();

    // 2. Initialize the sender
    sender_t my_sender;
    // For raw sockets, the IP/port here are less important as they are in the packet headers.
    // We pass NULL/0 to indicate this.
    if (sender_init(&my_sender, loop, target_ip, target_port) != 0) {
        fprintf(stderr, "Failed to initialize sender\n");
        return 1;
    }

    // 3. Prepare arguments for the packet creation function (`default_make`)
    default_make_args_t packet_args = {
        .src_ip = src_ip,
        .dst_ip = target_ip,
        .src_port = src_port,
        .dst_port = target_port,
        .domain_name = domain_name
    };

    // 4. Create the "oneshot" strategy, passing in our packet creation function
    sender_strategy_s* strategy = create_strategy_oneshot(
        default_init,
        default_free,
        default_make,
        &packet_args,
        NULL,
        NULL
    );

    if (!strategy) {
        fprintf(stderr, "Failed to create strategy\n");
        sender_free(&my_sender);
        return 1;
    }

    sender_set_strategy(&my_sender, strategy);
    printf("[*] Starting sender. Packet generation will begin in a background thread.\n");
    sender_start(&my_sender);
    
    // 7. Run the libuv event loop.
    printf("[*] Running libuv event loop. The program will exit once all packets are sent.\n");
    uv_run(loop, UV_RUN_DEFAULT);

    // 8. Clean up resources
    printf("[*] Cleaning up sender and closing loop.\n");
    // sender_free also takes care of freeing the strategy and its data
    sender_free(&my_sender);
    uv_loop_close(loop);

    printf("[*] Test finished.\n");
    return 0;
}