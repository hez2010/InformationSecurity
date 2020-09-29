#define _CRT_SECURE_NO_WARNINGS
#ifndef DES_H
#define DES_H

#include <stdbool.h>
#include <malloc.h>
#include <stdio.h>

typedef unsigned long long uint64_t;
typedef unsigned long uint32_t;
typedef unsigned char uint8_t;

uint64_t des_block(uint64_t data, uint64_t key, bool is_encrypt);
void des_file(char* in_filename, char* out_filename, const char* key_filename, bool is_encrypt);

#endif
