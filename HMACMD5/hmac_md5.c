#include <malloc.h>
#include <memory.h>
#include <string.h>
#include <stdio.h>

typedef unsigned char u8;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef char i8;
typedef long i32;
typedef long long i64;

const u32 T[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

const u32 FF_s[] = {7, 12, 17, 22};
const u32 GG_s[] = {5, 9, 14, 20};
const u32 HH_s[] = {4, 11, 16, 23};
const u32 II_s[] = {6, 10, 15, 21};

typedef union state
{
    struct
    {
        u32 a, b, c, d;
    } self;
    u8 byte[16];
} state;

typedef union buffer
{
    u8 byte[64];
    u32 word[16];
} buffer;

typedef struct context
{
    state state;
    i32 x_len;
    u64 data_len;
    buffer x;
} context;

inline u32 lshift(u32 x, u32 n)
{
    return ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)));
}

inline u32 F(u32 x, u32 y, u32 z)
{
    return (x & y) | (~x & z);
}

inline u32 G(u32 x, u32 y, u32 z)
{
    return (x & z) | (y & (~z));
}

inline u32 H(u32 x, u32 y, u32 z)
{
    return x ^ y ^ z;
}

inline u32 I(u32 x, u32 y, u32 z)
{
    return y ^ (x | (~z));
}

inline u32 FF(u32 a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 ac)
{
    a += F(b, c, d) + x + ac;
    a = lshift(a, s);
    a += b;
    return a;
}

inline u32 GG(u32 a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 ac)
{
    a += G(b, c, d) + x + ac;
    a = lshift(a, s);
    a += b;
    return a;
}

inline u32 HH(u32 a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 ac)
{
    a += H(b, c, d) + x + ac;
    a = lshift(a, s);
    a += b;
    return a;
}

inline u32 II(u32 a, u32 b, u32 c, u32 d, u32 x, u32 s, u32 ac)
{
    a += I(b, c, d) + x + ac;
    a = lshift(a, s);
    a += b;
    return a;
}

inline void rotate(context *input)
{
    u32 tmp = input->state.self.d;
    input->state.self.d = input->state.self.c;
    input->state.self.c = input->state.self.b;
    input->state.self.b = input->state.self.a;
    input->state.self.a = tmp;
}

void md5_transform(context *ctx)
{
    u32 last_a = ctx->state.self.a, last_b = ctx->state.self.b, last_c = ctx->state.self.c, last_d = ctx->state.self.d;
    i32 index = 0;
    for (i32 i = 0; i < 16; i++)
    {
        ctx->state.self.a = FF(ctx->state.self.a, ctx->state.self.b, ctx->state.self.c, ctx->state.self.d, ctx->x.word[index], FF_s[i % 4], T[i]);
        index = (index + 1) % 16;
        rotate(ctx);
    }
    index = 1;
    for (i32 i = 16; i < 32; i++)
    {
        ctx->state.self.a = GG(ctx->state.self.a, ctx->state.self.b, ctx->state.self.c, ctx->state.self.d, ctx->x.word[index], GG_s[i % 4], T[i]);
        index = (index + 5) % 16;
        rotate(ctx);
    }
    index = 5;
    for (i32 i = 32; i < 48; i++)
    {
        ctx->state.self.a = HH(ctx->state.self.a, ctx->state.self.b, ctx->state.self.c, ctx->state.self.d, ctx->x.word[index], HH_s[i % 4], T[i]);
        index = (index + 3) % 16;
        rotate(ctx);
    }
    index = 0;
    for (i32 i = 48; i < 64; i++)
    {
        ctx->state.self.a = II(ctx->state.self.a, ctx->state.self.b, ctx->state.self.c, ctx->state.self.d, ctx->x.word[index], II_s[i % 4], T[i]);
        index = (index + 7) % 16;
        rotate(ctx);
    }

    ctx->state.self.a += last_a;
    ctx->state.self.b += last_b;
    ctx->state.self.c += last_c;
    ctx->state.self.d += last_d;
}

void md5_init(context *ctx)
{
    memset(ctx, 0, sizeof(context));
    ctx->state.self.a = 0x67452301;
    ctx->state.self.b = 0xefcdab89;
    ctx->state.self.c = 0x98badcfe;
    ctx->state.self.d = 0x10325476;
}

void md5_update(context *ctx, u8 *data, i32 len)
{
    while (len > 0)
    {
        i32 size = len > 64 - ctx->x_len ? 64 - ctx->x_len : len;
        memcpy(ctx->x.byte + ctx->x_len, data, size);
        data += size;
        len -= size;
        ctx->x_len += size;
        ctx->data_len += size;
        if (ctx->x_len >= 64)
        {
            md5_transform(ctx);
            ctx->x_len = 0;
        }
    }
}

void md5_final(context *ctx)
{
    i32 index = 0;
    if (ctx->x_len >= 56)
    {
        while (ctx->x_len < 64)
        {
            ctx->x.byte[ctx->x_len++] = index++ == 0 ? 0x80 : 0;
        }
        md5_transform(ctx);
        ctx->x_len = 0;
    }
    else
    {
        while (ctx->x_len < 56)
        {
            ctx->x.byte[ctx->x_len++] = index++ == 0 ? 0x80 : 0;
        }
    }
    for (i32 i = 0; i < 8; ++i)
    {
        ctx->x.byte[56 + i] = (u8)((ctx->data_len * 8) >> (i * 8));
    }
    md5_transform(ctx);
    ctx->x_len = 0;
}

void hmac_init(char *key, char *input, i32 key_len, i32 input_len, u8 **ipad_out, u8 **opad_out)
{
    if (key_len > 64)
    {
        context ctx;
        md5_init(&ctx);
        md5_update(&ctx, key, key_len);
        md5_final(&ctx);
        key = ctx.state.byte;
        key_len = 16;
    }
    char *ipad = (char *)malloc(sizeof(char) * (64 + input_len));
    for (i32 i = 0; i < 64; i++)
    {
        ipad[i] = (i >= key_len ? 0 : key[i]) ^ 0x36;
    }
    memcpy(ipad + 64, input, sizeof(char) * input_len);
    *ipad_out = ipad;

    char *opad = (char *)malloc(sizeof(char) * (64 + 16));
    for (i32 i = 0; i < 64; i++)
    {
        opad[i] = (i >= key_len ? 0 : key[i]) ^ 0x5c;
    }
    memcpy(opad + 64, input, sizeof(char) * 16);
    *opad_out = opad;
}

i32 main(i32 argc, i8 **argv)
{
    if (argc < 2) {
        printf("HMAC-MD5 Usage:\n");
        printf("./HMACMD5 [keyfile] [inputfile]");
        return 0;
    }
    u8 buffer[64 + 16];
    context ctx;
    FILE* keyfile = fopen(*(argv + 1), "rb");
    FILE* msgfile = fopen(*(argv + 2), "rb");
    fseek(keyfile, 0, SEEK_END);
    fseek(msgfile, 0, SEEK_END);
    i32 keylen = ftell(keyfile);
    i32 msglen = ftell(msgfile);

    char *key = (char*)malloc(keylen * sizeof(char));
    char *msg = (char*)malloc(msglen * sizeof(char));

    fseek(keyfile, 0, SEEK_SET);
    fseek(msgfile, 0, SEEK_SET);
    fread(key, sizeof(char), keylen, keyfile);
    fread(msg, sizeof(char), msglen, msgfile);

    u8 *ipad, *opad;
    hmac_init(key, msg, keylen, msglen, &ipad, &opad);
    md5_init(&ctx);
    md5_update(&ctx, ipad, 64 + msglen);
    md5_final(&ctx);
    memcpy(buffer, opad, 64);
    memcpy(buffer + 64, ctx.state.byte, 16);
    free(ipad);
    free(opad);
    md5_init(&ctx);
    md5_update(&ctx, buffer, 64 + 16);
    md5_final(&ctx);
    printf("%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x%0.2x\n", ctx.state.byte[0], ctx.state.byte[1], ctx.state.byte[2], ctx.state.byte[3], ctx.state.byte[4], ctx.state.byte[5], ctx.state.byte[6], ctx.state.byte[7], ctx.state.byte[8], ctx.state.byte[9], ctx.state.byte[10], ctx.state.byte[11], ctx.state.byte[12], ctx.state.byte[13], ctx.state.byte[14], ctx.state.byte[15]);
    return 0;
}
