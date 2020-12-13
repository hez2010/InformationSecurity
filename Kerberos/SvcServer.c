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
    servaddr.sin_port = htons(42021);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(server, (struct sockaddr*)&servaddr, sizeof(servaddr));
    listen(server, 5);
    printf("Service Server: listen on 0.0.0.0:42021\n");
    char ipstr[INET6_ADDRSTRLEN];
    while (true) {
        int client;
        if ((client = accept(server, NULL, NULL)) == -1) {
            printf("[Error] Accept client: %s (errno: %d)\n", strerror(errno), errno);
            continue;
        }
        struct sockaddr_storage addr;
        socklen_t len = sizeof(struct sockaddr_storage);
        getpeername(client, (struct sockaddr*)&addr, &len);

        unsigned short port = ntohs(((struct sockaddr_in*)&addr)->sin_port);
        inet_ntop(AF_INET, &((struct sockaddr_in*)&addr)->sin_addr, ipstr, sizeof ipstr);

        Message msgE, msgG;

        receive_message(client, &msgE);
        u8* serviceTicketBuffer = NULL;
        u64 serviceTicketLen = des_buffer(msgE.data + sizeof(int), msgE.length - sizeof(int), SsKey, false, &serviceTicketBuffer);
        ServiceTicket serviceTicket;
        int serviceId;
        memcpy(&serviceId, msgE.data, sizeof(int));
        memcpy(&serviceTicket, serviceTicketBuffer, serviceTicketLen);
        free(serviceTicketBuffer);

        printf("[Info] Handle client request: client id = %d, service id = %d, client address: %s:%d\n", serviceTicket.id, serviceId, ipstr, (int)port);
        
        receive_message(client, &msgG);
        u8* clientBuffer = NULL;
        u64 clientLen = des_buffer(msgG.data, msgG.length, serviceTicket.key, false, &clientBuffer);
        Client clientData;
        memcpy(&clientData, clientBuffer, clientLen);
        free(clientBuffer);

        clientData.timestamp++;
        Message msgH = {};
        msgH.length = des_buffer((u8*)&clientData, sizeof(Client), serviceTicket.key, true, &msgH.data);
        send_message(client, &msgH);

        free(msgE.data);
        free(msgG.data);
        free(msgH.data);

        printf("[Info] Processed client request, client_id = %d, service_id = %d\n", serviceTicket.id, serviceId);

        close(client);
    }
}
