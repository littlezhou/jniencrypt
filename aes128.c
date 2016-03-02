#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>

int chartoint(char car);
unsigned char * extochar(unsigned char * in, int inLen) 
{
	int idx = 0, i; 
	int len = strlen(in);
	unsigned char *p = (unsigned char*)malloc(inLen);
	memset(p, 0, inLen);
	for( i = 0; i < len/2; i+=2, idx++ )
	{
		p[idx] = (in[i] & 0x40 ? in[i] & 0xF + 9 : in[i] & 0xF) << 4;
		p[idx] += in[i+1] & 0x40 ? in[i+1] & 0xF + 9 : in[i+1] & 0xF;
	}
	return p;
}

struct ctr_state { 
    unsigned char ivec[16];   
    unsigned int num; 
    unsigned char ecount[16]; 
}; 

void init_ctr(struct ctr_state *state, const unsigned char iv[16]){
    state->num = 0; 
    memset(state->ecount, 0, 16); 
    memcpy(state->ivec, iv, 16);
} 

void main(){
    unsigned char * cypher = extochar("874d6191b620e3261bef6864990db6ce",32);
    unsigned char * key = extochar("2b7e151628aed2a6abf7158809cf4f3c",32);
    unsigned char * iv = extochar("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",32);
    unsigned char out[256]; //more than needed
    AES_KEY aes_key;
    int msg_len = 16;
    struct ctr_state status; 

    if (!AES_set_encrypt_key(key, 16, &aes_key)){
        printf("key error"); 
        exit(-1);
    }

    init_ctr(&status, iv);

    AES_ctr128_encrypt(cypher, out, msg_len, &aes_key, status.ivec, status.ecount, &status.num);
//expected plaintext: "6bc1bee22e409f96e93d7e117393172a"
}
