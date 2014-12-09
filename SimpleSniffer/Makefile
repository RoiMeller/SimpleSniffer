# SimpleCLpacketSniffer Makefile

CC = gcc
CFLAGS += -g -Wall
LFLAGS += -lcap
OUTPUT += simpleCLpacketSniffer
OBJS += simpleCLpacketSniffer.o

default: all

%.o: %.c
	@echo "compiling... " $<
	@$(CC) -c $(CFLAGS) -o $@ $<

$(OUTPUT): $(OBJS)
	@echo "Linking " $@
	@$(CC) $< $(LFLAGS) -o $@

all: $(OUTPUT)

clean:
	@rm -f $(OBJS)
	@rm -f $(OUTPUT)
	@echo Clean Complete.

.PHONY: clean all
