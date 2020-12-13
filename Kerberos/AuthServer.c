#include "Utils.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "DES.h"

int main() {
    srand(time(NULL));
    int server = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in servaddr = {};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(42001);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(server, (struct sockaddr*)&servaddr, sizeof(servaddr));
    listen(server, 5);
    printf("Authentication Server: listen on 0.0.0.0:42001\n");
    char ipstr[INET6_ADDRSTRLEN];
    while (true) {
        int client;
        if ((client = accept(server, NULL, NULL)) == -1) {
            printf("[Error] Accept client: %s (errno: %d)\n", strerror(errno), errno);
            continue;
        }
        Message msg;
        receive_message(client, &msg);
        if (msg.length != sizeof(int)) {
            printf("[Error] Malformed request\n");
            continue;
        }
        int clientId;
        memcpy(&clientId, msg.data, sizeof(int));
        free(msg.data);
        Ticket ticket = {};
        socklen_t len = sizeof(struct sockaddr_storage);
        getpeername(client, (struct sockaddr*)&ticket.addr, &len);

        unsigned short port = ntohs(((struct sockaddr_in*)&ticket.addr)->sin_port);
        inet_ntop(AF_INET, &((struct sockaddr_in*)&ticket.addr)->sin_addr, ipstr, sizeof ipstr);

        printf("[Info] Handle client request: client id = %d, client address: %s:%d\n", clientId, ipstr, (int)port);

        if (ClientId == clientId) {
            Message a = {}, b = {};
            a.data = (u8*)malloc(sizeof(u64));
            u64 key_tgs = (u64)rand() * (u64)rand();
            u64 des_result = des_block(key_tgs, ClientKey, true);
            memcpy(a.data, &des_result, sizeof(u64));
            a.length = sizeof(u64);
            send_message(client, &a);
            free(a.data);
            b.data = (u8*)malloc(sizeof(Ticket));
            b.length = sizeof(Ticket);
            ticket.id = clientId;
            ticket.validity = time(NULL) + 600;
            ticket.key = key_tgs;
            b.length = des_buffer((u8*)&ticket, sizeof(Ticket), TgsKey, true, &b.data);
            send_message(client, &b);
            free(b.data);
            printf("[Info] Request processed completed: client id = %d\n", clientId);
        }
        else {
            printf("[Info] Unrecognized client: client id = %d\n", clientId);
        }
        close(client);
    }
}
