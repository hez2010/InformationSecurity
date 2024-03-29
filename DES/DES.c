﻿#include "DES.h"

// IP
const int IP[] = {
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
};

// IP^-1
const int IP_INV[] = {
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
};

// E
const int E[] = {
    32,1,2,3,4,5,
    4,5,6,7,8,9,
    8,9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1
};

// SBOX
const int SBOX[8][64] = {
    // S1
    {
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    },
    // S2
    {
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    },
    // S3
    {
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    },
    // S4
    {
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    },
    // S5
    {
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    },
    // S6
    {
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    },
    // S7
    {
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    },
    // S8
    {
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    }
};

// P
const int P[] = {
    16,7,20,21,
    29,12,28,17,
    1,15,23,26,
    5,18,31,10,
    2,8,24,14,
    32,27,3,9,
    19,13,30,6,
    22,11,4,25
};

// PC-1
const int PC1[] = {
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};

// PC-2
const int PC2[] = {
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
};

// 通用置换算法
uint64_t transform(const int* table, uint64_t data, int bit_size, int count) {
    uint64_t ret = 0;
    for (int i = 0; i < count; i++) {
        ret = (ret << 1) | ((data >> (bit_size - *(table + i))) & 0x1);
    }

    return ret;
}

// S 盒
uint32_t sbox(uint64_t key) {
    const int shift_bit[] = { 0,5,1,2,3,4 };
    uint32_t ret = 0;

    for (int i = 0; i < 8; i++) {
        uint64_t row = 0, col = 0;
        // 计算行列号
        for (int j = 0; j < 6; j++) {
            if (j < 2) {
                row = (row << 1) | ((((key >> (42 - i * 6)) & 0x3F) >> (5 - shift_bit[j])) & 0x1);
            }
            else {
                col = (col << 1) | ((((key >> (42 - i * 6)) & 0x3F) >> (5 - shift_bit[j])) & 0x1);
            }
        }
        // 取 S 盒值并左移
        ret = (ret << 4) | ((uint32_t)SBOX[i][(row << 4) + col] & 0xF);
    }

    return ret;
}

// 对 64 位数据执行 DES 算法
uint64_t block(uint64_t data, uint64_t* subkeys, bool is_encrypt) {
    // 初始置换 IP
    uint64_t ip_ret = transform(IP, data, 64, 64);
    // 计算 LR
    uint32_t L = (uint32_t)((ip_ret >> 32) & 0xFFFFFFFF);
    uint32_t R = (uint32_t)(ip_ret & 0xFFFFFFFF);

    // 16 轮迭代 T
    for (int i = 0; i < 16; i++) {
        // E 扩展
        uint64_t ext_ret = transform(E, R, 32, 48);
        ext_ret ^= is_encrypt ? *(subkeys + i) : *(subkeys + 15 - i);
        // S 盒
        uint64_t sbox_ret = sbox(ext_ret);
        // P 置换
        uint32_t f_ret = (uint32_t)transform(P, sbox_ret, 32, 32);
        // 交换置换 W
        uint32_t temp = L;
        L = R;
        R = temp ^ f_ret;
    }
    // 组合 LR 到 64 位数据
    uint64_t exchange_ret = ((uint64_t)L) | ((uint64_t)R << 32);
    // 逆置换 IP^-1
    uint64_t ret = transform(IP_INV, exchange_ret, 64, 64);
    return ret;
}

// 子密钥生成
void gen_subkeys(uint64_t key, uint64_t* subkeys) {
    // PC-1 置换
    uint64_t pc1_ret = transform(PC1, key, 64, 56);
    uint32_t C = (pc1_ret >> 28) & 0xFFFFFFF;
    uint32_t D = pc1_ret & 0xFFFFFFF;
    const int shift_bit[] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };
    for (int i = 0; i < 16; i++) {
        // 循环左移
        for (int j = 0; j < shift_bit[i]; j++) {
            C = ((C << 1) & 0xFFFFFFF) | ((C >> 27) & 0x1);
            D = ((D << 1) & 0xFFFFFFF) | ((D >> 27) & 0x1);
        }
        // 组合 CD 到 56 位数据
        uint64_t CD = ((uint64_t)C << 28) | (uint64_t)D;
        // PC-2 置换
        *(subkeys + i) = transform(PC2, CD, 56, 48);
    }
}

// DES 加解密算法
uint64_t des_block(uint64_t data, uint64_t key, bool is_encrypt) {
    uint64_t subkeys[16] = { 0 };
    gen_subkeys(key, subkeys);
    uint64_t ret = block(data, subkeys, is_encrypt);
    return ret;
}

uint64_t to_uint64(uint8_t* buffer) {
    uint64_t ret = 0;
    for (int i = 0; i < 8; i++) {
        ret = (ret << 8) | (uint64_t)(*(buffer + i));
    }
    return ret;
}

void to_bytes(uint64_t data, uint8_t* buffer) {
    for (int i = 0; i < 8; i++) {
        *(buffer + i) = (data >> (56 - 8 * i)) & 0xFF;
    }
}

void des_file(char* in_filename, char* out_filename, const char* key_filename, bool is_encrypt) {
    // 打开文件
    FILE* in_file = fopen(in_filename, "rb"),
        * out_file = fopen(out_filename, "wb+"),
        * key_file = fopen(key_filename, "rb");

    uint8_t buf[8] = { 0 };
    // 加载密钥
    fread(buf, sizeof(uint8_t), 8, key_file);
    uint64_t key = to_uint64(buf);
    fclose(key_file);

    fseek(in_file, 0, SEEK_END);
    uint64_t fsize = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);
    uint64_t buf_len = 0;
    // 每次处理 64 位数据
    while ((buf_len = fread(buf, sizeof(uint8_t), 8, in_file))) {
        // 每次减少读入的大小
        fsize -= buf_len;
        uint64_t ret = 0;
        int valid_len = 0;
        // 如果是加密则进行填充
        if (is_encrypt) {
            for (uint64_t i = buf_len; i < 8; i++) {
                buf[i] = (uint8_t)buf_len;
            }
            ret = des_block(to_uint64(buf), key, is_encrypt);
            valid_len = 8;
        }
        // 如果是解密则将最后不足 8 位的跳过
        else if (buf_len == 8) {
            ret = des_block(to_uint64(buf), key, is_encrypt);
            valid_len = fsize == 0 ? ((ret & 0xF) > 8 ? 8 : (ret & 0xF)) : 8;
        }
        to_bytes(ret, buf);
        // 写入文件
        fwrite(buf, sizeof(uint8_t), valid_len, out_file);
    }

    fclose(in_file);
    fclose(out_file);
}
