CC = gcc
CFLAGS = -g -Wall -O3 -pthread
LDFLAGS = -lm
TCP_SRC_DIR = ./tcp
TCP_SOURCES = $(wildcard $(TCP_SRC_DIR)/*.c) $(TCP_SRC_DIR)/main.c
TCP_OBJECTS = $(TCP_SOURCES:.c=.o)

IP_STACK_SRC_DIR = ./ip_stack
IP_STACK_SOURCES = $(filter-out $(IP_STACK_SRC_DIR)/main.c, $(wildcard $(IP_STACK_SRC_DIR)/*.c))
IP_STACK_OBJECTS = $(IP_STACK_SOURCES:.c=.o)

# IP Stack Program Variables
IP_STACK = ./ip_stack
IP_STACK_SOURCES_MAIN = $(wildcard $(IP_STACK_SRC_DIR)/*.c)
IP_STACK_OBJECTS_MAIN = $(IP_STACK_SOURCES_MAIN:.c=.o)
IP_STACK_TARGET = PING



TARGET = LAN_SPEED

all: $(TARGET) $(IP_STACK_TARGET)


$(TARGET):	$(TCP_OBJECTS) $(IP_STACK_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(IP_STACK_TARGET): $(IP_STACK_OBJECTS_MAIN)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: clean

clean:
	@rm -f $(TARGET) $(TCP_OBJECTS) $(IP_STACK_OBJECTS_) $(IP_STACK_OBJECTS_MAIN) core