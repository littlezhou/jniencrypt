#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

#define BLOCK_SIZE 16

int chartoint(char car) {
}

char *bytetohexstring(void *data, int len) {
	int i, j;
	char *table = "0123456789abcdef";
	unsigned char *p = (unsigned char *)data;
	char *r = (char*)malloc(len*2+1);
	r[len*2] = '\0';

	for( i=0, j=0; i<len; i++)
	{
		r[j++] = table[ p[i]>>4 ];
		r[j++] = table[ p[i] & 0xF ];
	}
	return r;
}

unsigned char * extochar(unsigned char * in, int inLen) 
{
	int idx = 0, i; 
	int len = strlen(in);
	unsigned char *p = (unsigned char*)malloc(inLen);
	memset(p, 0, inLen);
	for( i = 0; i < len; i+=2, idx++ )
	{
		p[idx] = ((in[i] & 0x40) ? (in[i] & 0xF) + 9 : (in[i] & 0xF)) << 4;
		p[idx] += (in[i + 1] & 0x40) ? (in[i + 1] & 0xF) + 9 : in[i + 1] & 0xF;
	}
	return p;
}

int phrase_hex(unsigned char * in, unsigned char *out)
{
	int idx = 0, i;
	int len = strlen(in);
	unsigned char *p = (unsigned char*)out;
	for( i = 0; i < len; i+=2, idx++ )
	{
		p[idx] = ((in[i] & 0x40) ? (in[i] & 0xF) + 9 : (in[i] & 0xF)) << 4;
		p[idx] += (in[i + 1] & 0x40) ? (in[i + 1] & 0xF) + 9 : in[i + 1] & 0xF;
	}
	return idx;
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

int cts128_encrypt(unsigned char *key, int keylen, unsigned char *data, int datalen, unsigned char *iv, unsigned char *out) {
	int ret = 0;
	AES_KEY aes_key;
	int nblocks = (datalen + BLOCK_SIZE -1)/BLOCK_SIZE;
	if (nblocks == 1) {

	} else if (nblocks > 1) {
		if (AES_set_encrypt_key(key, 128, &aes_key)<0){
			printf("key error");
			exit(-1);
		}
		ret = CRYPTO_cts128_encrypt(data, out, datalen, &aes_key, iv, (cbc128_f)AES_cbc_encrypt);
	}
	return ret;
}

int cts128_decrypt(unsigned char *key, int keylen, unsigned char *data, int datalen, unsigned char *iv, unsigned char *out) {
	int ret = 0;
	AES_KEY aes_key;
	int nblocks = (datalen + BLOCK_SIZE -1)/BLOCK_SIZE;
	if (nblocks == 1) {

	} else if (nblocks > 1) {
		if (AES_set_decrypt_key(key, 128, &aes_key)<0){
			printf("key error");
			exit(-1);
		}
		ret = CRYPTO_cts128_decrypt(data, out, datalen, &aes_key, iv, (cbc128_f)AES_cbc_encrypt);
	}
	return ret;
}

typedef size_t (*FUN_CTS128_CRYPT)(const unsigned char *in, unsigned char *out,  
                             size_t len, const void *key,  
                             unsigned char ivec[16], cbc128_f cbc);  

typedef void (*FUN_AES_CBC)(const unsigned char *in, unsigned char *out,  
       size_t len, const AES_KEY *key,  
       unsigned char *ivec, const int enc);

typedef int (*FUN_SET_KEY)(const unsigned char *userKey, const int bits,  AES_KEY *key);


int dl_encry(int encrypt, unsigned char *key, int keylen, unsigned char *data, int datalen, unsigned char *iv, unsigned char *out)  
{
	static FUN_CTS128_CRYPT cts_encrypt = NULL;
	static FUN_CTS128_CRYPT cts_decrypt = NULL;
	static FUN_AES_CBC	aes_cbc	    = NULL;
	static FUN_SET_KEY	set_en_key  = NULL;
	static FUN_SET_KEY	set_de_key  = NULL;

    char *err;
    void *so_handle;
    char soname[] = "/usr/lib64/libcrypto.so";

	int nblocks = 0;
	int ret = 0;
	AES_KEY aes_key;
	FUN_CTS128_CRYPT do_proc;
	FUN_SET_KEY	 set_key;

    if(cts_encrypt == NULL )
{
    so_handle = dlopen(soname, RTLD_LAZY);
    if (!so_handle) {  
        fprintf(stderr, "Error: load so `%s' failed./n", soname);  
        exit(-1);  
    }  
  
    dlerror(); 

    cts_decrypt = (FUN_CTS128_CRYPT)dlsym(so_handle, "CRYPTO_cts128_decrypt"); 
    err = dlerror();  
    if (NULL != err) {  
        fprintf(stderr, "%s/n", err);  
        exit(-1);  
    }

    cts_encrypt = (FUN_CTS128_CRYPT)dlsym(so_handle, "CRYPTO_cts128_encrypt"); 
    err = dlerror();  
    if (NULL != err) {  
        fprintf(stderr, "%s/n", err);  
        exit(-1);  
    }

    aes_cbc = (FUN_AES_CBC)dlsym(so_handle, "AES_cbc_encrypt"); 
    err = dlerror();  
    if (NULL != err) {  
        fprintf(stderr, "%s/n", err);  
        exit(-1);  
    }

    set_en_key = (FUN_SET_KEY)dlsym(so_handle, "AES_set_encrypt_key"); 
    err = dlerror();  
    if (NULL != err) {  
        fprintf(stderr, "%s/n", err);  
        exit(-1);  
    }

    set_de_key = (FUN_SET_KEY)dlsym(so_handle, "AES_set_decrypt_key"); 
    err = dlerror();  
    if (NULL != err) {  
        fprintf(stderr, "%s/n", err);  
        exit(-1);  
    }

    dlclose(so_handle);
}

	nblocks = (datalen + BLOCK_SIZE -1)/BLOCK_SIZE;
	if (nblocks == 1) {

	} else if (nblocks > 1) {
		do_proc = encrypt ? cts_encrypt : cts_decrypt;
		set_key = encrypt ? set_en_key : set_de_key;
		if (set_key(key, 128, &aes_key)<0){
			printf("key error");
			exit(-1);
		}
		ret = do_proc(data, out, datalen, &aes_key, iv, (cbc128_f)aes_cbc);
	}
	return ret;
}

void main(int argv, char *args[]){

    unsigned char * key = extochar(args[2],32);
    unsigned char * iv =  extochar(args[3],32);
    unsigned char msg[256], encoded[256]; //more than needed
    AES_KEY aes_key;
    int msg_len;

    printf("%s %d -> %s \n", "key", 16, bytetohexstring(key, 16));
    printf("%s %d -> %s \n", "iv ", 16, bytetohexstring(iv , 16));

    //char *tp = "173C28698191D82E8B97DF654A0D6F6D5468697320697320616E6F7468657220746573742E0A";
    msg_len = phrase_hex(args[1], msg);
    printf("%s %d -> %s \n", "msg", msg_len, bytetohexstring(msg, msg_len));

    //int encodedlen = cts128_encrypt(key, 16, msg, msg_len, iv, encoded);
    int encodedlen = dl_encry(1, key, 16, msg, msg_len, iv, encoded);
    printf("%s %d -> %s \n", "enc", encodedlen, bytetohexstring(encoded, encodedlen));
    //expected: 78a2e5861d44a7a4bb98ffa9510a8c7c9651496daa0b676339cca8988c358a37306a7091554c

    memset(iv, 0, 16);

    unsigned char decoded[256];
    //int decodedlen = cts128_decrypt(key, 16, encoded, encodedlen, iv, decoded);
    int decodedlen = dl_encry(0, key, 16, encoded, encodedlen, iv, decoded);
    printf("%s %d -> %s \n", "dec", decodedlen, bytetohexstring(decoded, decodedlen));
}
