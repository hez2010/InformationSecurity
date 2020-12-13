#define _CRT_SECURE_NO_WARNINGS
#ifndef Utils_h
#define Utils_h

#ifdef WIN32
#error Windows is not supported yet
#endif

#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdbool.h>

typedef unsigned long long u64;
typedef unsigned long u32;
typedef unsigned char u8;

#pragma pack(1)
typedef struct Message {
    u32 length;
    u8* data;
} Message;

typedef struct Ticket {
    int id;
    struct sockaddr_storage addr;
    u64 validity;
    u64 key;
} Ticket;

typedef struct Client {
    int id;
    u64 timestamp;
} Client;

typedef struct ServiceAuth {
    int id;
    u8* data;
} ServiceAuth;

typedef struct ServiceTicket {
    int id;
    struct sockaddr_storage addr;
    u64 validity;
    u64 key;
} ServiceTicket;

#pragma pack()

u32 message_to_buffer(Message* msg, u8** out);
void buffer_to_message(u8* buffer, Message* msg);
void send_message(int fd, Message* msg);
void receive_message(int fd, Message* msg);

extern const int ClientId;
extern const int ServiceId;
extern const u64 ClientKey;
extern const u64 TgsKey;
extern const u64 SsKey;

#endif // !Utils_h
