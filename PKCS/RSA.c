#include<gmp.h>
#include<stdlib.h>
#include<stdio.h>
#include<stdbool.h>
#include<time.h>
#include<malloc.h>
#include<memory.h>

typedef unsigned long long u64;

bool I2OSP(mpz_t x, int xLen, char** ret) {
    mpz_t base, r;
    mpz_init(base);
    mpz_init(r);
    mpz_init_set_ui(base, 256);
    mpz_pow_ui(r, base, xLen);
    int cmp = mpz_cmp(x, r);
    if (cmp >= 0) {
        return false;
    }

    mpz_t mod, iter;
    mpz_init(iter);
    mpz_init_set(iter, x);

    char* tmpRet = (char*)malloc(xLen);
    for (int i = xLen - 1; i >= 0; i--) {
        mpz_init(mod);
        mpz_mod_ui(mod, iter, 256);
        tmpRet[i] = mpz_get_ui(mod) & 0xff;
        mpz_div_ui(iter, iter, 256);
    }
    *ret = tmpRet;
    return true;
}

void OS2IP(char* x, u64 len, mpz_t* ret) {
    mpz_init(*ret);
    for (int i = 0; i < len; i++)
    {
        mpz_mul_ui(*ret, *ret, 256);
        mpz_add_ui(*ret, *ret, x[i] & 0xff);
    }
}

void RSAEP(mpz_t m, mpz_t e, mpz_t n, mpz_t* c) {
    mpz_init(*c);
    mpz_powm(*c, m, e, n);
}

void RSADP(mpz_t c, mpz_t d, mpz_t n, mpz_t* m) {
    mpz_init(*m);
    mpz_powm(*m, c, d, n);
}

int get_length(mpz_t x) {
    u64 len = mpz_sizeinbase(x, 2);
    return 1 + len / 8 + (len % 8 ? 1 : 0);
}

bool encrypt(char* M, u64 mLen, mpz_t e, mpz_t n, char** C) {
    int nLen = get_length(n);
    if (mLen > nLen - 11) {
        return false;
    }
    int psLen = nLen - mLen - 3;
    char* PS = (char*)malloc(psLen);
    for (int i = 0; i < psLen; i++) {
        PS[i] = (rand() % 0xff) + 1;
    }
    int emLen = psLen + mLen + 3;
    char* EM = (char*)malloc(emLen);
    EM[0] = 0;
    EM[1] = 2;
    for (int i = 0; i < psLen; i++) {
        EM[i + 2] = PS[i];
    }
    EM[psLen + 2] = 0;
    for (int i = 0; i < mLen; i++) {
        EM[i + 3 + psLen] = M[i];
    }
    mpz_t m, c;
    OS2IP(EM, emLen, &m);
    RSAEP(m, e, n, &c);
    free(PS);
    free(EM);
    return I2OSP(c, nLen, C);
}

bool decrypt(char* C, u64 cLen, mpz_t d, mpz_t n, char** M, int* mLen) {
    int nLen = get_length(n);
    if (cLen != nLen || nLen < 11) {
        return false;
    }
    mpz_t c, m;
    OS2IP(C, cLen, &c);
    RSADP(c, d, n, &m);
    int emLen = get_length(m);
    char* EM = NULL;
    I2OSP(m, emLen, &EM);
    if (EM[0] != 0 || EM[1] != 2) {
        return false;
    }
    int index = 0;
    for (int i = 2; i < emLen; i++) {
        if (EM[i] == 0) {
            index = i;
            break;
        }
    }
    if (index == 0) {
        return false;
    }
    char* tmpM = (char*)malloc(emLen - (index + 1));
    for (int i = index + 1; i < emLen; i++) {
        tmpM[i - (index + 1)] = EM[i];
    }
    *M = tmpM;
    *mLen = emLen - (index + 1);
    free(EM);
    return true;
}

void keygen(int bitLen, mpz_t* e, mpz_t* d, mpz_t* n) {
    gmp_randstate_t random;
    mpz_t p, q;
    while (true) {
        gmp_randinit_default(random);
        gmp_randseed_ui(random, time(NULL));
        mpz_init(p);
        mpz_init(q);
        mpz_urandomb(p, random, bitLen / 2 - 1);
        mpz_urandomb(q, random, bitLen / 2 + 1);
        mpz_nextprime(p, p);
        mpz_nextprime(q, q);
        mpz_init(*n);
        mpz_mul(*n, p, q);
        if (mpz_sizeinbase(*n, 2) == bitLen) {
            break;
        }
    }
    mpz_t phi;
    mpz_init(phi);
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi, p, q);
    mpz_init(*e);
    mpz_init(*d);
    mpz_init_set_ui(*e, 65537);
    mpz_invert(*d, *e, phi);
}

int keygen_mode(int bitLen, FILE* publicKey, FILE* privateKey) {
    mpz_t e, d, n;
    keygen(bitLen, &e, &d, &n);
    gmp_fprintf(publicKey, "%ZX,%ZX", n, e);
    gmp_fprintf(privateKey, "%ZX,%ZX", n, d);
    return 0;
}

int encrypt_mode(FILE* input, FILE* output, FILE* publicKey) {
    fseek(input, 0, SEEK_END);
    int len = ftell(input);
    fseek(input, 0, SEEK_SET);
    char* M = (char*)malloc(len);
    fread(M, sizeof(char), len, input);
    mpz_t n, e;
    mpz_init(n);
    mpz_init(e);
    gmp_fscanf(publicKey, "%ZX,%ZX", &n, &e);
    int outputLen = get_length(n);
    char* C = NULL;
    if (!encrypt(M, len, e, n, &C)) {
        printf("Failed to decrypt\n");
        return -1;
    }
    fwrite(C, sizeof(char), outputLen, output);
    free(M);
    free(C);
    return 0;
}

int decrypt_mode(FILE* input, FILE* output, FILE* privateKey) {
    fseek(input, 0, SEEK_END);
    int len = ftell(input);
    fseek(input, 0, SEEK_SET);
    char* C = (char*)malloc(len);
    fread(C, sizeof(char), len, input);
    mpz_t n, d;
    mpz_init(n);
    mpz_init(d);
    gmp_fscanf(privateKey, "%ZX,%ZX", &n, &d);
    int outputLen;
    char* M = NULL;
    if (!decrypt(C, len, d, n, &M, &outputLen)) {
        printf("Failed to encrypt\n");
        return -1;
    }
    fwrite(M, sizeof(char), outputLen, output);
    free(M);
    free(C);
    return 0;
}

void print_usage() {
    printf("RSA toolkit usage\n\n");
    printf("Encrypt: RSA encrypt inputfile publickeyfile outputfile\n");
    printf("Decrypt: RSA decrypt inputfile privatekeyfile outputfile\n");
    printf("Keygen: RSA keygen bitsize publickeyfile privatekeyfile\n\n");
    printf("Example: RSA keygen 2048 id_rsa.pub id_rsa\n");
}

int main(int argc, char** argv) {
    if (argc <= 2) goto arg_err;
    FILE* file1 = NULL, * file2 = NULL, * file3 = NULL;
    int ret = 0;
    switch (argv[1][0]) {
    case 'e': case 'E':
        if (argc < 5) goto arg_err;
        file1 = fopen(argv[2], "r");
        file2 = fopen(argv[3], "r");
        file3 = fopen(argv[4], "w");
        ret = encrypt_mode(file1, file3, file2);
        fclose(file1);
        fclose(file2);
        fclose(file3);
        goto ok;
        break;
    case 'd': case 'D':
        if (argc < 5) goto arg_err;
        file1 = fopen(argv[2], "r");
        file2 = fopen(argv[3], "r");
        file3 = fopen(argv[4], "w");
        ret = decrypt_mode(file1, file3, file2);
        fclose(file1);
        fclose(file2);
        fclose(file3);
        goto ok;
        break;
    case 'k': case 'K':
        if (argc < 5) goto arg_err;
        int bitsize = atoi(argv[2]);
        file1 = fopen(argv[3], "w");
        file2 = fopen(argv[4], "w");
        ret = keygen_mode(bitsize, file1, file2);
        fclose(file1);
        fclose(file2);
        goto ok;
        break;
    }

arg_err:
    print_usage();
    return -1;
ok:
    return ret;
}
