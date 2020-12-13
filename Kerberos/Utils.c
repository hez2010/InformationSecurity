#include "Utils.h"

const int ClientId = 101;
const int ServiceId = 233;
const u64 ClientKey = 233331145141919810;
const u64 TgsKey = 114514191981023333;
const u64 SsKey = 114514233331919810;

u32 message_to_buffer(Message* msg, u8** out) {
    u32 length = msg->length * sizeof(u8) + sizeof(u32);
    u8* buffer = (u8*)malloc(length);
    u32 offset = sizeof(msg->length);
    memcpy(buffer, &msg->length, offset);
    memcpy(buffer + offset, msg->data, msg->length);
    *out = buffer;
    return length;
}

void buffer_to_message(u8* buffer, Message* msg) {
    u32 length;
    memcpy(&length, buffer, sizeof(u32));
    msg->length = length;
    msg->data = (u8*)malloc(length * sizeof(u8));
    memcpy(msg->data, buffer + sizeof(u32), length);
}

void send_message(int fd, Message* msg) {
    u8* buffer;
    u32 length = message_to_buffer(msg, &buffer);
    send(fd, buffer, length, 0);
    free(buffer);
    printf("[Info] Sent message, length = %lu\n", length);
}

void receive_message(int fd, Message* msg) {
    u32 length;
    recv(fd, &length, sizeof(u32), 0);
    printf("[Info] Received message header, body length = %lu\n", length);
    u8* buffer = (u8*)malloc(length * sizeof(u8));
    recv(fd, buffer, length, 0);
    msg->length = length;
    msg->data = buffer;
    printf("[Info] Received message body\n");
}
