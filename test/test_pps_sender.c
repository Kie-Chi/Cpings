#include "sender.h"
#include "strategy.h"
#include "dns.h" // For dns_init

int main(int argc, char** argv) {
    // --- Test Parameters ---
    char* target_ip = "192.168.3.144";
    uint16_t target_port = 12345;
    uint16_t src_port = 53;
    char* domain_name = "example.com";
    char* src_ip = "192.168.3.131"; // Spoofed source IP

    // --- PPS Strategy Parameters ---
    uint32_t pps = 500;              // Target packets per second
    size_t high_watermark = 200;     // Refill buffer when it drops below this
    size_t packets_per_burst = 500;  // How many packets to generate in each background task

    printf("[*] PPS Test Configuration:\n");
    printf("    Target: %s:%u\n", target_ip, target_port);
    printf("    Rate: %u pps\n", pps);
    printf("    High Watermark: %zu packets\n", high_watermark);
    printf("    Generation Burst Size: %zu packets\n", packets_per_burst);
    printf("------------------------------------\n");

    // Initialize DNS subsystem for packet creation
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

    // 3. Prepare arguments for our new burst packet creation function
    uint32_t shared_txid_counter = 0; // This counter will be shared across all generation tasks

    default_make_args_t d_args = {
        .src_ip = src_ip,
        .dst_ip = target_ip,
        .src_port = src_port,
        .dst_port = target_port,
        .domain_name = domain_name
    };

    pps_make_args_t packet_args = {
        .default_args = d_args,
        .count = packets_per_burst
    };

    // 4. Create the "pps" strategy, passing in our new burst make function
    sender_strategy_t* strategy = create_strategy_pps(
        default_init,        // Use default queue init
        default_free,        // Use default queue free
        pps_make,      // Our new function to generate N packets
        &packet_args,        // Arguments for our new make function
        NULL,                // Use default send function
        NULL,                // No special send arguments
        pps,                 // The desired packets-per-second rate
        high_watermark       // The buffer's high watermark
    );

    if (!strategy) {
        fprintf(stderr, "Failed to create PPS strategy\n");
        sender_free(&my_sender);
        return 1;
    }
    printf("[+] PPS strategy created.\n");

    sender_set_strategy(&my_sender, strategy);

    // 5. Start the sender. This will start the PPS timer and trigger the first packet generation.
    printf("[*] Starting sender. PPS timer and producer will now run.\n");
    sender_start(&my_sender);
    
    // 6. Run the libuv event loop.
    // This will block and run until there are no more active handles (or uv_stop is called).
    // In our case, the pps_timer will keep the loop alive.
    printf("[*] Running libuv event loop. Press Ctrl+C to stop.\n");
    uv_run(loop, UV_RUN_DEFAULT);

    // 7. Clean up resources (this part will be reached if the loop is stopped)
    printf("[*] Cleaning up sender and closing loop.\n");
    sender_free(&my_sender);
    uv_loop_close(loop);

    printf("[*] Test finished.\n");
    return 0;
}