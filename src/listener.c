// ======== listener.c ========
#include "parser.h" // Include our new parser header

int main() {
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;
    uint8_t buffer[2048]; // A buffer to receive packets
    uint16_t bind_port = 12345;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(bind_port); // Listen on a non-privileged port

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("[+] Listening for a UDP packet on port %u...\n", bind_port);
    printf("[+] Send a DNS query to this listener, e.g., 'dig @127.0.0.1 -p %u google.com'\n", bind_port);

    socklen_t len = sizeof(cliaddr);
    ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&cliaddr, &len);

    if (n < 0) {
        perror("recvfrom failed");
        close(sockfd);
        return 1;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cliaddr.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf("\n[+] Packet received from %s:%d (%zd bytes)\n\n", client_ip, ntohs(cliaddr.sin_port), n);
    
    parsed_dns_packet_t dns_packet;
    if (unpack_dns_packet(buffer, n, &dns_packet)) {
        printf("-------------------- Parsed DNS Packet --------------------\n");
        print_parsed_dns_packet(&dns_packet);
        free_parsed_dns_packet(&dns_packet); // Don't forget to free the allocated memory!
    } else {
        fprintf(stderr, "[-] Failed to parse DNS packet.\n");
    }

    close(sockfd);
    return 0;
}