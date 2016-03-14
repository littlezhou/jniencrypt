#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/aes.h>


# define ALGOR_NUM       30
# define SIZE_NUM        5
# define RSA_NUM         4
# define DSA_NUM         3

static int lengths[SIZE_NUM] = { 16, 64, 256, 1024, 8 * 1024 };
# define BUFSIZE ((long)1024*8+1)

static const char *names[ALGOR_NUM] = {
    "md2", "mdc2", "md4", "md5", "hmac(md5)", "sha1", "rmd160", "rc4",
    "des cbc", "des ede3", "idea cbc", "seed cbc",
    "rc2 cbc", "rc5-32/12 cbc", "blowfish cbc", "cast cbc",
    "aes-128 cbc", "aes-192 cbc", "aes-256 cbc",
    "camellia-128 cbc", "camellia-192 cbc", "camellia-256 cbc",
    "evp", "sha256", "sha512", "whirlpool",
    "aes-128 ige", "aes-192 ige", "aes-256 ige", "ghash"
};

#define print_result(a, b, c, d) 

# define D_CBC_128_AES   16

# define D_EVP           22

#  define COND(c) (run && count<0x7fffffff)

static void print_message(const char *s, long num, int length)
{
	int mr = 0;
    printf(mr ? "+DN:%s:%ld:%d\n"
               : "Doing %s %ld times on %d size blocks: ", s, num, length);
}


void output_result(struct timeval stm, struct timeval etm, int round, int blocksize);

void init()
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
}

#define Time_F(x) 

void cryxxxx(int useEVP) {

  struct timeval stm[SIZE_NUM], etm[SIZE_NUM];
  double tm_comp;

  static const unsigned char key16[16] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12
    };
static unsigned char iv[64];

unsigned char md[100];


  int j;
  const EVP_CIPHER *evp_cipher = NULL;
  const EVP_MD *evp_md = NULL;
  char *algo = "aes-128-cbc";

  int decrypt = 0;
  int count, save_count;

	int nround = 599999;

  AES_KEY aes_ks1, aes_ks2, aes_ks3;

  unsigned char *buf = NULL, *buf2 = NULL;

  if ((buf = (unsigned char *)OPENSSL_malloc((int)BUFSIZE)) == NULL) {
      printf( "out of memory\n");
      return;
  }
  if ((buf2 = (unsigned char *)OPENSSL_malloc((int)BUFSIZE)) == NULL) {
      printf( "out of memory\n");
      return;
  }

init();

  evp_cipher = EVP_get_cipherbyname(algo);
  if (!evp_cipher) {
      evp_md = EVP_get_digestbyname(algo);
      if( !evp_md ) {
      printf("Error ------ \n");
      return;
    }
  }

  AES_set_encrypt_key(key16, 128, &aes_ks1);

  if (useEVP) {
        for (j = 0; j < SIZE_NUM; j++) {
            if (evp_cipher) {
                EVP_CIPHER_CTX ctx;
                int outl;

                names[D_EVP] = OBJ_nid2ln(evp_cipher->nid);
                /*
                 * -O3 -fschedule-insns messes up an optimization here!
                 * names[D_EVP] somehow becomes NULL
                 */
                print_message(names[D_EVP], save_count, lengths[j]);

                EVP_CIPHER_CTX_init(&ctx);
                if (decrypt)
                    EVP_DecryptInit_ex(&ctx, evp_cipher, NULL, key16, iv);
                else
                    EVP_EncryptInit_ex(&ctx, evp_cipher, NULL, key16, iv);
                EVP_CIPHER_CTX_set_padding(&ctx, 0);

                gettimeofday(&stm[j], NULL);
                if (decrypt)
                    for (count = 0;
                         count < nround; count++)
                        EVP_DecryptUpdate(&ctx, buf, &outl, buf, lengths[j]);
                else
                    for (count = 0;
                         count < nround;
                         count++)
                        EVP_EncryptUpdate(&ctx, buf, &outl, buf, lengths[j]);
                if (decrypt)
                    EVP_DecryptFinal_ex(&ctx, buf, &outl);
                else
                    EVP_EncryptFinal_ex(&ctx, buf, &outl);
                gettimeofday(&etm[j], NULL);

                EVP_CIPHER_CTX_cleanup(&ctx);
            }
            if (evp_md) {
                names[D_EVP] = OBJ_nid2ln(evp_md->type);
                print_message(names[D_EVP], save_count, lengths[j]);

                gettimeofday(&stm[j], NULL);
                for (count = 0; count < nround; count++)
                    EVP_Digest(buf, lengths[j], &(md[0]), NULL, evp_md, NULL);

                gettimeofday(&etm[j], NULL);
            }
            //print_result(D_EVP, j, count, d);
            output_result(stm[j], etm[j], nround, lengths[j]);
        }
    } else {
        for (j = 0; j < SIZE_NUM; j++) {
            //print_message(names[D_CBC_128_AES], c[D_CBC_128_AES][j], lengths[j]);
            gettimeofday(&stm[j], NULL);
            for (count = 0; count < nround; count++)
                AES_cbc_encrypt(buf, buf, (unsigned long)lengths[j], &aes_ks1, iv, AES_ENCRYPT);
            gettimeofday(&etm[j], NULL);
            //print_result(D_CBC_128_AES, j, count, d);
            output_result(stm[j], etm[j], nround, lengths[j]);
        }
    }
}



int main(int argc, char *argv[])
{
  int useEVP = 0;
  useEVP = argc>1?1:0;
	cryxxxx( useEVP );
  return 0;
}



double getseconds(struct timeval last, struct timeval current) {
  int sec, usec;

  sec = current.tv_sec - last.tv_sec;
  usec = current.tv_usec - last.tv_usec;
  return ( (double)sec + usec*((double)(1e-6)) );
}

void output_result(struct timeval stm, struct timeval etm, int round, int blocksize)
{
  double tm_comp = getseconds(stm, etm);
  double outlen = round * 1.0 * blocksize;
  printf("Iter=%d time=%0.3fms time/round=%0.3fms size=%0.3fMB/s\n",
                        round, tm_comp * 1000.0, tm_comp *1000.0 /round, outlen/1024.0/1024/tm_comp);
}
