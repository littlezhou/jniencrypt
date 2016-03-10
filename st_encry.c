#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

#define BLOCK_SIZE 16

double getseconds(struct timeval last, struct timeval current);

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


int test_cbc128(int encrypt, unsigned char *key, unsigned char *data, size_t datalen, unsigned char *iv, unsigned char *out) {
	int encr, outlen;
	EVP_CIPHER_CTX *ctx = ( EVP_CIPHER_CTX * )malloc( sizeof(EVP_CIPHER_CTX ));
	EVP_CIPHER_CTX_init( ctx );
	outlen = datalen;

	if ( encrypt ) {
		EVP_EncryptInit_ex( ctx, EVP_aes_128_cbc(), NULL, key, iv );
		encr = EVP_EncryptUpdate( ctx, out, &outlen, data, datalen );
	} else {
		EVP_DecryptInit_ex( ctx, EVP_aes_128_cbc(), NULL, key, iv );
		encr = EVP_DecryptUpdate( ctx, out, &outlen, data, datalen );
	}

	EVP_CIPHER_CTX_cleanup( ctx );
	free( ctx );
	return encr;
}


int test_cbc128_encry(int encrypt, unsigned char *key, unsigned char *data, size_t datalen, unsigned char *iv, unsigned char *out) {
	if(encrypt)
	{
		CRYPTO_cbc128_encrypt(data, out, datalen, key, iv, (block128_f)AES_encrypt);
	}
	else
	{
		CRYPTO_cbc128_decrypt(data, out, datalen, key, iv, (block128_f)AES_encrypt);
	}
	return (int)datalen;
}


void test()
{
	struct timeval stm, etm;
	double tm_comp;
	int i;
	int datalen = 16 * 1024 * 1024;
	int outlen = 0;
	unsigned char *data, *out;
	int round = 200;

	unsigned char *key, *iv;
	data= (unsigned char*)malloc(datalen);
	key = (unsigned char*)malloc(16);
	iv  = (unsigned char*)malloc(16);
	memset(iv, 0, 16);


	for(i=0; i<datalen; i++)
	{
		data[i] = i%26 + 'A';
	}

	for(i=0; i<16; i++)
	{
		key[i] = i%26 + 'A';
	}

	out = data;
	//out= (unsigned char*)malloc(datalen);

	printf("data=%p key=%p iv=%p out=%p \n", data, key, iv, out);
	gettimeofday(&stm, NULL);

	for(i=0; i<round; i++)
	{
		outlen += cts128_encrypt(key, 16, data, datalen, iv, out);
		//outlen += dl_encry(1, key, 16, data, datalen, iv, out);
		//outlen += dl_aes_128_ctr(1, key, 16, data, datalen, iv, out);
		//outlen += test_cbc128_encry(1, key, data, datalen, iv, out);
		//outlen += test_cbc128(1, key, data, datalen, iv, out);
		//printf("%s %d -> %s \n", "res", 16, bytetohexstring(out, 16));
	}

	gettimeofday(&etm, NULL);
	tm_comp = getseconds(stm, etm) *1000.0;
	printf("Iter=%d time=%0.3fms time/round=%0.3fms size=%0.3fMB\n",
                        round, tm_comp, tm_comp/round, outlen/1024.0/1024);
}

void main(int argv, char *args[]){

	return test();
}



double getseconds(struct timeval last, struct timeval current) {
  int sec, usec;

  sec = current.tv_sec - last.tv_sec;
  usec = current.tv_usec - last.tv_usec;
  return ( (double)sec + usec*((double)(1e-6)) );
}
