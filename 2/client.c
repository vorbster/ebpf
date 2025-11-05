// client.c
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

// Client-side: Simple full-buffer send/receive for contrast (no inefficiency here)

int main(int argc, char *argv[]) {
    const char *server_ip = (argc > 1) ? argv[1] : "127.0.0.1";  // Allow remote IP as arg
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];
    char send_buffer[BUFFER_SIZE];
    time_t t;

    // Seed random
    srand((unsigned) time(&t));

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 address (supports remote)
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address %s / Address not supported \n", server_ip);
        return -1;
    }

    // Connect
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed to %s\n", server_ip);
        return -1;
    }

    printf("Connected to server at %s:%d\n", server_ip, PORT);

    while (1) {
        // Prepare random data to send (full buffer)
        for (int i = 0; i < BUFFER_SIZE; i++) {
            send_buffer[i] = (char)(rand() % 256);
        }

        // Send random data (full buffer)
        send(sock, send_buffer, BUFFER_SIZE, 0);

        // Receive data (full buffer; inefficiency is on server side)
        int valread = recv(sock, buffer, BUFFER_SIZE, 0);
        if (valread <= 0) {
            perror("recv");
            break;
        }

        // Note: Due to server's byte-by-byte sends, recv may block longer or show low throughput
        printf("Client received %d bytes (check server for inefficiency)\n", valread);
    }

    close(sock);
    return 0;
}
