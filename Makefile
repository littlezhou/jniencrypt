
allbin=aes128 aes_cts_128 dlload_encry

all: $(allbin)
	g++ -shared -fPIC -O0 -g -o libencypxx.so encry_impl.cpp -I/usr/lib/jvm/java-1.8.0/include -I/usr/lib/jvm/java-1.8.0/include/linux  -lssl

%: %.c
	gcc $< -std=c99 -g -lssl -o $@

clean:
	@rm -f $(allbin)
	@rm -f *.so
