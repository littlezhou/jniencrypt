
allbin=aes128 aes_cts_128

all: $(allbin)
	g++ -shared -fPIC -g -O0 -o libencypxx.so encry_impl.cpp -I/usr/lib/jvm/java-1.7.0-openjdk.x86_64/include -I/usr/lib/jvm/java-1.7.0-openjdk.x86_64/include/linux  -lssl

%: %.c
	gcc $< -std=c99 -g -lssl -o $@

clean:
	@rm -f $(allbin)
	@rm -f *.so
