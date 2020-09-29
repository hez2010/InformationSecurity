#include "DES.h"

int main(int argc, char** argv) {
    if (argc < 5) {
        printf("usage: DES.exe -[E|D] key input output\n\n\t-E\tEncrypt a file.\n\t-D\tDecrypt a file.\n\nExample: DES.exe -E key.bin input.bin output.bin");
    }
    bool is_encrypt = (*(argv + 1))[1] == 'E';
    des_file(*(argv + 3), *(argv + 4), *(argv + 2), is_encrypt);

    return 0;
}
