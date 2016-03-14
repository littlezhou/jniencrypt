
allbin=aes128 aes_cts_128 dlload_encry st_encry

all: $(allbin)
	g++ -shared -fPIC -O0 -g -o libencypxx.so encry_impl.cpp -I/usr/lib/jvm/java-1.8.0/include -I/usr/lib/jvm/java-1.8.0/include/linux  -lssl

%: %.c
	gcc $< -std=c99 -g -O0 -lssl -o $@

clean:
	@rm -f $(allbin)
	@rm -f *.so

st_encry:
	gcc st_encry.c -std=c99 -g -O0 -o st_encry -ldl 

openssltest:
	gcc openssltest.c -o openssltest -lcrypto -lssl


# gcc st_encry.c -std=c99 -g -O0 -o st_encry -ldl -L/root/Downloads/openssl-1.0.1s -lcrypto
# gcc speed.c  -o x -I/root/Downloads/openssl-1.0.1s -lcrypto -lssl
