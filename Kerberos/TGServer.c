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
    servaddr.sin_port = htons(42011);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(server, (struct sockaddr*)&servaddr, sizeof(servaddr));
    listen(server, 5);
    printf("TG Server: listen on 0.0.0.0:42011\n");
    char ipstr[INET6_ADDRSTRLEN];
    while (true) {
        int client;
        if ((client = accept(server, NULL, NULL)) == -1) {
            printf("[Error] Accept client: %s (errno: %d)\n", strerror(errno), errno);
            continue;
        }
        ServiceTicket svcTicket = {};
        socklen_t len = sizeof(struct sockaddr_storage);
        getpeername(client, (struct sockaddr*)&svcTicket.addr, &len);

        unsigned short port = ntohs(((struct sockaddr_in*)&svcTicket.addr)->sin_port);
        inet_ntop(AF_INET, &((struct sockaddr_in*)&svcTicket.addr)->sin_addr, ipstr, sizeof ipstr);

        Message msgC, msgD;

        receive_message(client, &msgC);
        ServiceAuth service = {};
        memcpy(&service.id, msgC.data, sizeof(int));
        printf("[Info] Handle client request: service id = %d, client address: %s:%d\n", service.id, ipstr, (int)port);
        service.data = (u8*)malloc(msgC.length - sizeof(int));
        memcpy(service.data, msgC.data + sizeof(int), msgC.length - sizeof(int));
        free(msgC.data);
        u8* ticketBuffer;
        Ticket ticket = {};
        u8 ticketLen = des_buffer(service.data, msgC.length - sizeof(int), TgsKey, false, &ticketBuffer);
        memcpy(&ticket, ticketBuffer, ticketLen);
        free(ticketBuffer);

        receive_message(client, &msgD);
        u8* clientBuffer = NULL;
        u64 clientLen = des_buffer(msgD.data, msgD.length, ticket.key, false, &clientBuffer);
        Client* clientData;
        memcpy(&clientData, clientBuffer, clientLen);
        free(clientBuffer);

        svcTicket.id = ticket.id;
        svcTicket.validity = ticket.validity;
        svcTicket.key = (u64)rand() * (u64)rand();

        Message e = {}, f = {};
        u8* eData = NULL;
        e.length = sizeof(int) + des_buffer((u8*)&svcTicket, sizeof(ServiceTicket), SsKey, true, &eData);
        e.data = (u8*)malloc(e.length);
        memcpy(e.data, &service.id, sizeof(int));
        memcpy(e.data + sizeof(int), eData, e.length - sizeof(int));
        free(eData);
        f.length = sizeof(u64);
        u64 encryptedKey = des_block(svcTicket.key, ticket.key, true);
        f.data = (u8*)malloc(sizeof(u64));
        memcpy(f.data, &encryptedKey, sizeof(u64));

        send_message(client, &e);
        send_message(client, &f);

        free(e.data);
        free(f.data);

        printf("[Info] Processed client request, service_id = %d\n", service.id);

        close(client);
    }
}
