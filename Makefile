CFLAGS=-c -g -Wall -Wextra -Wpedantic -O0 -I. `pkg-config --cflags openssl`
LDFLAGS=`pkg-config --libs openssl`
CC=gcc

all: initiator responder

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $<

initiator: initiator.o socket.o crypto.o helper.o
	gcc -o initiator $^ $(LDFLAGS)

responder: responder.o socket.o crypto.o helper.o
	gcc -o responder $^ $(LDFLAGS)

clean:
	rm -f *.o initiator responder
