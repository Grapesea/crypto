#include <stdio.h>
#include <string.h>
#include <openssl/des.h>

//md5(flag)的起始字节为0x89
//

void encrypt(unsigned char bufin[], unsigned char bufout[], unsigned char key[])
{
    DES_cblock *pin, *pout;
    des_key_schedule ks;
    pin = (DES_cblock*)bufin;
    pout = (DES_cblock*)bufout;
    des_set_key((DES_cblock *)key, ks);
    des_ecb_encrypt(pin, pout, ks, DES_ENCRYPT);
}
void decrypt(unsigned char bufin[], unsigned char bufout[], unsigned char key[])
{
    DES_cblock *pin, *pout;
    des_key_schedule ks;
    pin = (DES_cblock*)bufin;
    pout = (DES_cblock*)bufout;
    des_set_key((DES_cblock *)key, ks);
    des_ecb_encrypt(pin, pout, ks, DES_DECRYPT);
}