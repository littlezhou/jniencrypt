#include <jni.h>
#include <jni_md.h>
//#include </home/directory-kerby/kerby-kerb/kerb-crypto/src/main/java/org_apache_kerby_kerberos_kerb_crypto_enc_provider_OpenSSLNative.h>
#include </home/Kerby/directory-kerby/kerby-kerb/kerb-crypto/src/main/java/org_apache_kerby_kerberos_kerb_crypto_enc_provider_OpenSSLNative.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <dlfcn.h>

#define BLOCK_SIZE 16
void dl_symbols();


int chartoint(char car) {
}

char *bytetohexstring(void *data, int len) {
	int i, j;
	char *table = (char *)("0123456789abcdef");
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
	int len = strlen((char*)in);
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
	int len = strlen((char *)in);
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

void dl_symbols();

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
	static FUN_CTS128_CRYPT cts_encrypt = NULL;
	static FUN_CTS128_CRYPT cts_decrypt = NULL;
	static FUN_AES_CBC	aes_cbc	    = NULL;
	static FUN_SET_KEY	set_en_key  = NULL;
	static FUN_SET_KEY	set_de_key  = NULL;



typedef void (*FUN_EVP_CIPHER_INIT)(EVP_CIPHER_CTX *a);
typedef int (*FUN_EVP_INIT)(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
typedef EVP_CIPHER * (*FUN_EVP_CIPHER)(void);
typedef int (*FUN_EVP_CIPHER_CTX_SET_PADDING)(EVP_CIPHER_CTX *x, int padding);
typedef int (*FUN_EVP_UPDATE)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl);
typedef int (*FUN_EVP_FINAL)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
typedef int (*FUN_EVP_CIPHER_CTX_CLEANUP)(EVP_CIPHER_CTX *a);

static FUN_EVP_CIPHER_INIT 	fc_ctx_init = NULL;
static FUN_EVP_INIT		fc_en_init  = NULL;
static FUN_EVP_INIT		fc_de_init  = NULL;
static FUN_EVP_CIPHER		fc_aes_128_cbc = NULL;
static FUN_EVP_CIPHER_CTX_SET_PADDING fc_set_padding = NULL;
static FUN_EVP_UPDATE		fc_en_update= NULL;
static FUN_EVP_UPDATE		fc_de_update= NULL;
static FUN_EVP_FINAL		fc_en_final = NULL;
static FUN_EVP_FINAL		fc_de_final = NULL;
static FUN_EVP_CIPHER_CTX_CLEANUP fc_cleanup = NULL;


typedef int (*FUN_EVP_CipherInit_EX)(EVP_CIPHER_CTX *, const EVP_CIPHER *,  \
           ENGINE *, const unsigned char *, const unsigned char *, int);

static FUN_EVP_CIPHER		fc_aes_128_ctr = NULL;
static FUN_EVP_UPDATE		fc_ctr_update =  NULL;
static FUN_EVP_CipherInit_EX  	fc_CipherInit_EX = NULL;

int dl_aes_128_ctr(int encrypt, unsigned char *key, int keylen, unsigned char *data, int datalen, unsigned char *iv, unsigned char *out)
{
	FUN_EVP_UPDATE c_update;
	int ret, outlen = datalen;
	EVP_CIPHER_CTX ctx;
int i=0;
while(i);
	if(cts_encrypt == NULL )
		dl_symbols();

	c_update = fc_ctr_update;

        fc_ctx_init(&ctx);

	ret = fc_CipherInit_EX(&ctx, fc_aes_128_ctr(), NULL, key, iv, encrypt);
        if (ret == 0) {
                return 0;
        }
        fc_set_padding(&ctx, 0);
        ret = c_update(&ctx, out, &outlen, data, datalen);
        fc_cleanup(&ctx);
        return outlen;
}


int dl_cbc_encry (int encrypt, unsigned char *key, unsigned char *iv, unsigned char *data, int datalen, unsigned char *out) {
	FUN_EVP_INIT c_init = encrypt ? fc_en_init : fc_de_init;
	FUN_EVP_UPDATE c_update = encrypt ? fc_en_update : fc_de_update;
	FUN_EVP_FINAL c_final = encrypt ? fc_en_final : fc_de_final;
        int ret = 0, outlen, leftlen ;
        EVP_CIPHER_CTX ctx;
        fc_ctx_init(&ctx);

        ret = c_init(&ctx, fc_aes_128_cbc(), NULL, key, iv);
        if (ret == 0) {
                return 0;
        }
        fc_set_padding(&ctx, 0);
        if (!c_update(&ctx, out, &outlen, data, datalen))
		return 0;

	if (!c_final(&ctx, out + outlen, &leftlen))
		return 0;
	memcpy(iv, ctx.iv, 16);
        fc_cleanup(&ctx);
        return datalen;
}

// datalen > 16 bytes
int do_cts_evp_encrypt(int encrypt, unsigned char *data, unsigned char *out,
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

	dl_cbc_encry (encrypt, key, iv, data, datalen, out);

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
	dl_cbc_encry (encrypt, key, iv, tmp.c, BLOCK_SIZE, out - BLOCK_SIZE);
#endif
    return datalen + residue;
}



int dl_encry(int encrypt, unsigned char *key, unsigned char *data, int datalen, unsigned char *iv, unsigned char *out)  
{
	int nblocks = 0;
	int ret = 0;
	AES_KEY aes_key;
	FUN_CTS128_CRYPT do_proc;
	FUN_SET_KEY	 set_key;

	if(cts_encrypt == NULL )
		dl_symbols();

	nblocks = (datalen + BLOCK_SIZE -1)/BLOCK_SIZE;
	if (nblocks > 1) {
		/*
		do_proc = encrypt ? cts_encrypt : cts_decrypt;
		set_key = encrypt ? set_en_key : set_de_key;
		if (set_key(key, 128, &aes_key)<0){
			printf("key error");
			exit(-1);
		}
		ret = do_proc(data, out, datalen, &aes_key, iv, (cbc128_f)aes_cbc);
		*/
		ret = do_cts_evp_encrypt(encrypt, data, out, datalen, key, iv);
	} else if (nblocks == 1) {
		if (datalen != BLOCK_SIZE) {
			return 0;
		}
		ret = dl_cbc_encry (encrypt, key, iv, data, BLOCK_SIZE, out);
	}
	return ret;
}

unsigned char *st_data = NULL;

JNIEXPORT jbyteArray JNICALL Java_org_apache_kerby_kerberos_kerb_crypto_enc_provider_OpenSSLNative_doEncryptAes128
  (JNIEnv * env, jobject obj, jbyteArray jdata, jbyteArray jkey, jbyteArray jiv, jboolean jencrypt) 
{
	jbyte *pjdata = env->GetByteArrayElements(jdata, 0);
	unsigned char *data = (unsigned char*)pjdata;
	int datalen = env->GetArrayLength(jdata);

	jbyte *pjkey = env->GetByteArrayElements(jkey, 0);
	unsigned char *key = (unsigned char*)pjkey;
	int keylen = env->GetArrayLength(jkey);

	jbyte *pjiv = env->GetByteArrayElements(jiv, 0);
	unsigned char *iv = (unsigned char*)pjiv;
	int ivlen = env->GetArrayLength(jiv);
//FILE *fp = fopen("/tmp/jni_dbg.log", "wa+");
//fprintf(fp, "%s %d -> %s \n", "data", datalen, bytetohexstring(data, datalen)); fflush(fp);
//fprintf(fp, "%s %d -> %s \n", "key", keylen, bytetohexstring(key, keylen)); fflush(fp);
//fprintf(fp, "%s %d -> %s \n", "iv ", ivlen, bytetohexstring(iv , ivlen)); fflush(fp);
	if (0 && st_data == NULL) {
		st_data = (unsigned char*)malloc(16*1024*1024);
	}

	bool encrypt = jencrypt == JNI_TRUE;
	//unsigned char *buf = (unsigned char *)malloc(datalen +64);
	//int retlen = encrypt ? cts128_encrypt(nkey, 16, ndata, datalen, niv, buf) :
	//			cts128_decrypt(nkey, 16, ndata, datalen, niv, buf);
	int retlen = dl_encry(encrypt?1:0, key, data, datalen, iv, data);
	//int retlen = dl_aes_128_ctr(encrypt?1:0, key, 16, data, datalen, iv, data);

//fprintf(fp, "%s %d -> %s \n", "ret", retlen, bytetohexstring(buf, retlen)); fflush(fp); 
//fclose(fp);
	//memcpy(data, buf, retlen);
	jbyteArray jret = env->NewByteArray(retlen);
	env->SetByteArrayRegion(jret, 0, retlen, pjdata);
	env->ReleaseByteArrayElements(jret, pjdata, JNI_ABORT);

	env->ReleaseByteArrayElements(jkey, pjkey, JNI_ABORT);
	env->ReleaseByteArrayElements(jiv,  pjiv, JNI_ABORT);

	//free(buf);
	return jret;
}




/*
void main(){
    unsigned char * key = extochar("49CB7071A3281DFADFE055438E6A5723",32);
    unsigned char * iv =  extochar("00000000000000000000000000000000",32);
    unsigned char msg[256], encoded[256]; //more than needed
    AES_KEY aes_key;
    int msg_len;

    printf("%s %d -> %s \n", "key", 16, bytetohexstring(key, 16));
    printf("%s %d -> %s \n", "iv ", 16, bytetohexstring(iv , 16));

    char *tp = "173C28698191D82E8B97DF654A0D6F6D5468697320697320616E6F7468657220746573742E0A";
    msg_len = phrase_hex(tp, msg);
    printf("%s %d -> %s \n", "msg", msg_len, bytetohexstring(msg, msg_len));

    int encodedlen = cts128_encrypt(key, 16, msg, msg_len, iv, encoded);
    printf("%s %d -> %s \n", "enc", encodedlen, bytetohexstring(encoded, encodedlen));
    //expected: 78a2e5861d44a7a4bb98ffa9510a8c7c9651496daa0b676339cca8988c358a37306a7091554c

    memset(iv, 0, 16);

    unsigned char decoded[256];
    int decodedlen = cts128_decrypt(key, 16, encoded, encodedlen, iv, decoded);
    printf("%s %d -> %s \n", "dec", decodedlen, bytetohexstring(decoded, decodedlen));
} */


void dl_symbols() {
    if(cts_encrypt == NULL )
{
    char *err;
    void *so_handle;
    char soname[] = "/usr/lib64/libcrypto.so";


    so_handle = dlopen(soname, RTLD_LAZY);
    if (!so_handle) {  
        fprintf(stderr, "Error: load so `%s' failed.\n", soname);  
        exit(-1);  
    }  
  
    dlerror(); 

    cts_decrypt = (FUN_CTS128_CRYPT)dlsym(so_handle, "CRYPTO_cts128_decrypt"); 
    err = dlerror();  
    if (NULL != err) {  
        fprintf(stderr, "%s\n", err);  
        exit(-1);  
    }

    cts_encrypt = (FUN_CTS128_CRYPT)dlsym(so_handle, "CRYPTO_cts128_encrypt"); 
    err = dlerror();  
    if (NULL != err) {  
        fprintf(stderr, "%s\n", err);  
        exit(-1);  
    }

    aes_cbc = (FUN_AES_CBC)dlsym(so_handle, "AES_cbc_encrypt"); 
    err = dlerror();  
    if (NULL != err) {  
        fprintf(stderr, "%s\n", err);  
        exit(-1);  
    }

    set_en_key = (FUN_SET_KEY)dlsym(so_handle, "AES_set_encrypt_key"); 
    err = dlerror();  
    if (NULL != err) {  
        fprintf(stderr, "%s\n", err);  
        exit(-1);  
    }

    set_de_key = (FUN_SET_KEY)dlsym(so_handle, "AES_set_decrypt_key"); 
    err = dlerror();  
    if (NULL != err) {  
        fprintf(stderr, "%s\n", err);  
        exit(-1);  
    }

    fc_ctx_init = (FUN_EVP_CIPHER_INIT)dlsym(so_handle, "EVP_CIPHER_CTX_init");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }

    fc_en_init = (FUN_EVP_INIT)dlsym(so_handle, "EVP_EncryptInit_ex");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }

    fc_de_init = (FUN_EVP_INIT)dlsym(so_handle, "EVP_DecryptInit_ex");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }

    fc_aes_128_cbc = (FUN_EVP_CIPHER)dlsym(so_handle, "EVP_aes_128_cbc");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }

    fc_aes_128_ctr = (FUN_EVP_CIPHER)dlsym(so_handle, "EVP_aes_128_ctr");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }

    fc_set_padding = (FUN_EVP_CIPHER_CTX_SET_PADDING)dlsym(so_handle, "EVP_CIPHER_CTX_set_padding");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }

    fc_en_update = (FUN_EVP_UPDATE)dlsym(so_handle, "EVP_EncryptUpdate");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }

    fc_de_update = (FUN_EVP_UPDATE)dlsym(so_handle, "EVP_DecryptUpdate");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }

    fc_en_final = (FUN_EVP_FINAL)dlsym(so_handle, "EVP_EncryptFinal_ex");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }

    fc_de_final = (FUN_EVP_FINAL)dlsym(so_handle, "EVP_DecryptFinal_ex");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }

    fc_ctr_update = (FUN_EVP_UPDATE)dlsym(so_handle, "EVP_CipherUpdate");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }

    fc_cleanup = (FUN_EVP_CIPHER_CTX_CLEANUP)dlsym(so_handle, "EVP_CIPHER_CTX_cleanup");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }

    fc_CipherInit_EX = (FUN_EVP_CipherInit_EX)dlsym(so_handle, "EVP_CipherInit_ex");
    err = dlerror();
    if (NULL != err) {
        fprintf(stderr, "%s\n", err);
        exit(-1);
    }
    dlclose(so_handle);
}
}


