CC = cc
CFLAGS = -Wall -O2
LDFLAGS = -lssl -lcrypto

server: server.c
	$(CC) $(CFLAGS) server.c -o server $(LDFLAGS)

clean:
	rm -f server