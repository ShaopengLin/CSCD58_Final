CC=gcc
CFLAGS=-Wall -pthread

# Object files
OBJS=main.o utils.o sendpacket.o protocol.o handlepacket.o


# Your program's name
PROGRAM=myprogram

# Default target
all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) $(CFLAGS) -o $(PROGRAM) $(OBJS)

main.o: main.c utils.h sendpacket.h
	$(CC) $(CFLAGS) -c main.c

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c utils.c

sendpacket.o: sendpacket.c protocol.h
	$(CC) $(CFLAGS) -c sendpacket.c

handlepacket.o: handlepacket.c protocol.h
	$(CC) $(CFLAGS) -c handlepacket.c

protocol.o: protocol.c protocol.h
	$(CC) $(CFLAGS) -c protocol.c

clean:
	rm -f $(OBJS) $(PROGRAM)
