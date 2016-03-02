
allbin=aes128 aes_cts_128

all: $(allbin)

%: %.c
	gcc $< -std=c99 -g -lssl -o $@

clean:
	@rm -f $(allbin)
