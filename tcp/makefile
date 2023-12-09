CC = gcc
CFLAGS = -g -Wall -O3 -pthread
LDFLAGS = -lm
TCP_SOURCES = tcp_testmain.c tcp_protocol.c tcp_op.c mt19937ar.c
TCP_OBJECTS = $(TCP_SOURCES:.c=.o)
TARGET = tcp

$(TARGET):	$(TCP_OBJECTS) 
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	@rm -f $(TARGET) $(TCP_OBJECTS) core