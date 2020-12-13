#include <netinet/in.h>
#include <unistd.h>
#include <time.h>

#include "DES.h"
#include "Utils.h"

int main() {
    printf("Client: Kerberos authentication, client_id = %d, service_id = %d\n", ClientId, ServiceId);
    int authServer = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in servaddr = {};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(42001);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    printf("[Info] Connect to Authentication Server\n");
    connect(authServer, (struct sockaddr*)&servaddr, sizeof(servaddr));
    Message msg = {};
    msg.data = malloc(sizeof(int));
    memcpy(msg.data, &ClientId, sizeof(int));
    msg.length = sizeof(int);
    send_message(authServer, &msg);

    Message msgA, msgB;
    receive_message(authServer, &msgA);
    receive_message(authServer, &msgB);
    close(authServer);

    u64 sessionTgs = 0;
    memcpy(&sessionTgs, msgA.data, sizeof(u64));
    free(msgA.data);
    u64 tgs_key = des_block(sessionTgs, ClientKey, false);

    servaddr.sin_port = htons(42011);
    int tgsServer = socket(AF_INET, SOCK_STREAM, 0);
    printf("[Info] Connect to TG Server\n");
    connect(tgsServer, (struct sockaddr*)&servaddr, sizeof(servaddr));

    Message msgC = {}, msgD = {};

    msgC.length = sizeof(int) + msgB.length;
    msgC.data = (u8*)malloc(sizeof(int) + msgB.length);

    memcpy(msgC.data, &ServiceId, sizeof(int));
    memcpy(msgC.data + sizeof(int), msgB.data, msgB.length);
    free(msgB.data);

    Client client = {};
    client.id = ClientId;
    client.timestamp = time(NULL);
    
    msgD.length = des_buffer((u8*)&client, sizeof(Client), tgs_key, true, &msgD.data);
    send_message(tgsServer, &msgC);
    send_message(tgsServer, &msgD);
    free(msgC.data);
    free(msgD.data);

    Message msgE, msgF;
    receive_message(tgsServer, &msgE);
    receive_message(tgsServer, &msgF);
    u64 sessionSs = 0;
    memcpy(&sessionSs, msgF.data, sizeof(u64));
    free(msgF.data);
    u64 ss_key = des_block(sessionSs, tgs_key, false);
    close(tgsServer);

    servaddr.sin_port = htons(42021);
    int svcServer = socket(AF_INET, SOCK_STREAM, 0);
    printf("[Info] Connect to Service Server\n");
    connect(svcServer, (struct sockaddr*)&servaddr, sizeof(servaddr));

    send_message(svcServer, &msgE);
    free(msgE.data);
    Message msgG = {};
    msgG.length = des_buffer((u8*)&client, sizeof(Client), ss_key, true, &msgG.data);
    send_message(svcServer, &msgG);
    free(msgG.data);

    Message msgH;
    receive_message(svcServer, &msgH);

    u8* clientBuffer = NULL;
    u64 clientLen = des_buffer(msgH.data, msgH.length, ss_key, false, &clientBuffer);
    Client clientData;
    memcpy(&clientData, clientBuffer, clientLen);
    free(clientBuffer);
    free(msgH.data);

    if (clientData.timestamp == client.timestamp + 1) {
        printf("[Info] Kerberos authentication succeeded, original timestamp: %llu, reponse timestamp: %llu\n", client.timestamp, clientData.timestamp);
    }
    else {
        printf("[Error] Failed to authenticate with Kerberos, original timestamp: %llu, reponse timestamp: %llu\n", client.timestamp, clientData.timestamp);
    }

    return 0;
}
