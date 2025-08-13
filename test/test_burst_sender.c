#include "sender.h"
#include "strategy.h"
#include "dns.h" // For dns_init

#define BURST_DELAY_S 2    // 2-second delay before the first burst
#define BURST_INTERVAL_S 5 // Repeat a burst every 5 seconds
#define PACKETS_PER_BURST 10000 // How many packets to generate and send in each burst

int main(int argc, char** argv) {
    // --- Test Parameters ---
    char* target_ip = "192.168.3.144";
    uint16_t target_port = 12345;
    uint16_t src_port = 53;
    char* domain_name = "example-burst.com";
    char* src_ip = "192.168.3.131"; // Spoofed source IP

    uint64_t delay_ms = BURST_DELAY_S * 1000;
    uint64_t interval_ms = BURST_INTERVAL_S * 1000; 

    printf("[*] Burst Test Configuration:\n");
    printf("    Target: %s:%u\n", target_ip, target_port);
    printf("    Initial Delay: %llu ms\n", (unsigned long long)delay_ms);
    printf("    Repeat Interval: %llu ms\n", (unsigned long long)interval_ms);
    printf("    Packets per Burst: %d\n", PACKETS_PER_BURST); // New print statement
    printf("------------------------------------\n");

    dns_init();

    // 1. Initialize libuv event loop
    uv_loop_t* loop = uv_default_loop();

    // 2. Initialize the sender
    sender_t my_sender;
    if (sender_init(&my_sender, loop, target_ip, target_port) != 0) {
        fprintf(stderr, "Failed to initialize sender\n");
        return 1;
    }
    printf("[+] Sender initialized.\n");

    // 3. Prepare arguments for the packet creation function.

    default_make_args_t d_args = {
        .src_ip = src_ip,
        .dst_ip = target_ip,
        .src_port = src_port,
        .dst_port = target_port,
        .domain_name = domain_name
    };

    pps_make_args_t packet_args = {
        .default_args = d_args,
        .count = PACKETS_PER_BURST, // <<< Control the burst size here
    };

    // 4. Create the "burst" strategy.
    sender_strategy_t* strategy = create_strategy_burst(
        default_init,
        default_free,
        pps_make,   // <<< Use the burst-aware make function
        &packet_args,     // <<< Pass the pps_make_args_t struct
        NULL,             // Use default send function
        NULL,
        delay_ms,         // Initial delay
        interval_ms       // Repeat interval (0 for single shot)
    );

    if (!strategy) {
        fprintf(stderr, "Failed to create Burst strategy\n");
        sender_free(&my_sender);
        return 1;
    }
    printf("[+] Burst strategy created.\n");

    sender_set_strategy(&my_sender, strategy);

    // 5. Start the sender. This will start the burst timer.
    printf("[*] Starting sender. Timer is set. First burst will trigger in %d seconds.\n", BURST_DELAY_S);
    sender_start(&my_sender);
    
    // 6. Run the libuv event loop.
    printf("[*] Running libuv event loop. Press Ctrl+C to stop.\n");
    uv_run(loop, UV_RUN_DEFAULT);

    // 7. Clean up
    printf("[*] Cleaning up sender and closing loop.\n");
    sender_free(&my_sender);
    uv_loop_close(loop);

    printf("[*] Test finished.\n");
    return 0;
}