CC = gcc
CFLAGS = -g -Wall -O3 -pthread
LDFLAGS = -lm
TCP_SRC_DIR = ./tcp
TCP_SOURCES = $(wildcard $(TCP_SRC_DIR)/*.c) main.c
TCP_OBJECTS = $(TCP_SOURCES:.c=.o)

IP_STACK_SRC_DIR = ./ip_stack
IP_STACK_SOURCES = $(wildcard $(IP_STACK_SRC_DIR)/*.c)
IP_STACK_OBJECTS = $(IP_STACK_SOURCES:.c=.o)
TARGET = LAN_SPEED

$(TARGET):	$(TCP_OBJECTS) $(IP_STACK_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	@rm -f $(TARGET) $(TCP_OBJECTS) $(IP_STACK_OBJECTS) core