#define _CRT_SECURE_NO_WARNINGS
#ifndef DES_H
#define DES_H

#include "Utils.h"
#include <stdbool.h>
#include <malloc.h>
#include <stdio.h>

u64 des_block(u64 data, u64 key, bool is_encrypt);
void des_file(char* in_filename, char* out_filename, const char* key_filename, bool is_encrypt);
u64 des_buffer(u8* buffer, u64 len, u64 key, bool is_encrypt, u8** out);

#endif // !DES_H
