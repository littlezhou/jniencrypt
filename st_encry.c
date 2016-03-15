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

int test_aes_cbc_128(int encrypt, unsigned char *key, unsigned char *data, size_t datalen, unsigned char *iv, unsigned char *out)
{
	AES_KEY aes_key;
	if(encrypt)
		AES_set_encrypt_key(key, 128, &aes_key);
	else
		AES_set_decrypt_key(key, 128, &aes_key);
	AES_cbc_encrypt(data, out, datalen, &aes_key, iv, encrypt);
	return datalen;
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

int do_cbc_evp_encrypt(unsigned char *data, int datalen, unsigned char *key, unsigned char *iv, unsigned char *out )
{
    int outlen, leftlen;
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(&ctx, 0);
    if(!EVP_EncryptUpdate(&ctx, out, &outlen, data, datalen))
    {
        return 0; // error
    }

    if(!EVP_EncryptFinal_ex(&ctx, out + outlen, &leftlen))
    {
        return 0;
    }
    outlen += leftlen;
    memcpy(iv, ctx.iv, 16);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return outlen;
}

void init()
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
}

int do_cbc_evp_encrypt__round(unsigned char *data, int datalen, unsigned char *key, unsigned char *iv, unsigned char *out, int nround)
{
    int i, outlen, leftlen;

    char *algo = "aes-128-cbc";
    const EVP_CIPHER *evp_cipher = NULL;

//init();
    //evp_cipher = EVP_get_cipherbyname(algo);

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);   //EVP_aes_128_cbc()
    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    for(i = 0; i<nround; i++)
    {
	    if(!EVP_EncryptUpdate(&ctx, out, &outlen, data, datalen))
	    {
	        return 0; // error
	    }
	}

		if(!EVP_EncryptFinal_ex(&ctx, data, &leftlen))
	    //if(!EVP_EncryptFinal_ex(&ctx, out + outlen, &leftlen))
	    {
	        return 0;
	    }
	


    EVP_CIPHER_CTX_cleanup(&ctx);
    return 1;
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


int do_cts_evp_encrypt(unsigned char *data, unsigned char *out,
                             size_t datalen, unsigned char *key,
                             unsigned char iv[16])
{
    size_t residue;
    union {
        size_t align;
        unsigned char c[16];
    } tmp;

    AES_KEY aes_key;

    if(!(data && out && key && iv)) {
		return 0;
	}

    if (datalen <= 16)
        return 0;

    if ((residue = datalen % 16) == 0)
        residue = 16;

    datalen -= residue;


    //(*cbc) (data, out, datalen, key, iv, 1);
	do_cbc_evp_encrypt(data, datalen, key, iv, out);

    data += datalen;
    out += datalen;

#if defined(CBC_HANDLES_TRUNCATED_IO)
    memcpy(tmp.c, out - 16, 16);
    (*cbc) (data, out - 16, residue, key, iv, 1);
    memcpy(out, tmp.c, residue);
#else
    memset(tmp.c, 0, sizeof(tmp));
    memcpy(tmp.c, data, residue);
    memcpy(out, out - 16, residue);
    //(*cbc) (tmp.c, out - 16, 16, key, iv, 1);
	do_cbc_evp_encrypt(tmp.c, 16, key, iv, out - 16);
#endif
    return datalen + residue;
}


/*
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
*/

static unsigned char key16[16] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12
    };

void test()
{
	struct timeval stm, etm;
	double tm_comp;
	int i;
	int datalen = 16*1204*1024; //24;// 16*1024*1024;  // 8*1024; 
	int ret;
	double outlen = 0;
	unsigned char *data, *out;
	int round = 200;   //599999;
	
	int dbg = 0;

	unsigned char *key, *iv;
	data= (unsigned char*)malloc(datalen);
//data = (unsigned char *)OPENSSL_malloc( datalen +1 );

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

//key = key16;
	out = data;
	//out= (unsigned char*)malloc(datalen);

	printf("data=%p key=%p iv=%p out=%p \n", data, key, iv, out);
	printf("%s %d -> %s \n", "res", datalen, bytetohexstring(out, datalen>32?32:datalen));
	printf("%s %d -> %s \n", "key", 16, bytetohexstring(key, 16));
	printf("%s %d -> %s \n", "iv ", 16, bytetohexstring(iv , 16));
	printf("\n\n");
	gettimeofday(&stm, NULL);

	for(i=0; i<round; i++)
	{
		ret = cts128_encrypt(key, 16, data, datalen, iv, out);
		//ret = do_cts_evp_encrypt(data, out, datalen, key, iv);
		
		//ret = test_cbc128_encry(1, key, data, datalen, iv, out);  // Error
		//ret = test_cbc128(1, key, data, datalen, iv, out);
		//ret = test_aes_cbc_128(1, key, data, datalen, iv, out);
		//ret = do_cbc_evp_encrypt(data, datalen, key, iv, out);
		outlen += ret;

		//ret = do_cbc_evp_encrypt__round(data, datalen, key, iv, out, round);
		//outlen = round* 1.0 * datalen ;
		//break;
	}
	gettimeofday(&etm, NULL);

	unsigned long *puid = OPENSSL_ia32cap_loc();
	printf("UID: %016llX \n", *puid);
	
	printf("%s %d -> %s \n", "res", datalen, bytetohexstring(out, datalen>32?32:datalen));
		printf("%s %d -> %s \n", "key", 16, bytetohexstring(key, 16));
		printf("%s %d -> %s \n", "iv ", 16, bytetohexstring(iv , 16));

	tm_comp = getseconds(stm, etm);
	printf("Iter=%d time=%0.3fms time/round=%0.3fms size=%0.3fMB/s\n",
                        round, tm_comp * 1000.0, tm_comp *1000.0 /round, outlen/1024.0/1024/tm_comp);
}

#define SET_BIT(V, idx) ((V) | (((unsigned long)1)<<(idx)))

void main(int argv, char *args[]){
/*	unsigned long *puid = OPENSSL_ia32cap_loc();
	unsigned long myid = ~0;
	myid = SET_BIT(myid, 4);
	myid = SET_BIT(myid, 23);
	myid = SET_BIT(myid, 25);
	myid = SET_BIT(myid, 26);
	myid = SET_BIT(myid, 41);
	myid = SET_BIT(myid, 57);
	myid = SET_BIT(myid, 60);
	*puid = (*puid) | (myid);
	printf("UID: %016llX \n", *puid); */
	return test();
}



double getseconds(struct timeval last, struct timeval current) {
  int sec, usec;

  sec = current.tv_sec - last.tv_sec;
  usec = current.tv_usec - last.tv_usec;
  return ( (double)sec + usec*((double)(1e-6)) );
}
