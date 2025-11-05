// server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Buggy networking function: Sends data byte-by-byte in a tight loop
// This causes excessive syscalls (send/write per byte), leading to high networking overhead,
// poor throughput, and kernel-level inefficiency traceable via eBPF on sys_send/sys_write stacks.
void buggy_send_data(int sock_fd, char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        // Tight loop with individual sends - no buffering, each a syscall
        if (send(sock_fd, &data[i], 1, 0) < 0) {
            perror("send");
            break;
        }
        // Optional: Minimal delay to simulate "paced" sending, but still inefficient
        // usleep(1);  // Uncomment for even more realism (micro-delays add overhead)
    }
    printf("Sent %zu bytes inefficiently (byte-by-byte)\n", len);
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];
    char send_buffer[BUFFER_SIZE];
    time_t t;

    // Seed random
    srand((unsigned) time(&t));

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;  // Bind to all interfaces for remote access
    address.sin_port = htons(PORT);

    // Bind
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d (all interfaces)\n", PORT);

    // Accept client (single client for simplicity; supports remote)
    if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // Log client IP for demo
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf("Client connected from %s\n", client_ip);

    while (1) {
        // Receive data (full buffer for contrast)
        int valread = recv(client_fd, buffer, BUFFER_SIZE, 0);
        if (valread <= 0) {
            perror("recv");
            break;
        }

        // Prepare random data to send back
        for (int i = 0; i < BUFFER_SIZE; i++) {
            send_buffer[i] = (char)(rand() % 256);
        }

        // Send data inefficiently (this is where the bug is - excessive small sends)
        buggy_send_data(client_fd, send_buffer, BUFFER_SIZE);
    }

    close(client_fd);
    close(server_fd);
    return 0;
}
