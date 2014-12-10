# SimpleCLpacketSniffer Makefile

CC = gcc
CFLAGS += -g -Wall
LFLAGS += -lcap

OUTPUT += simpleCLpacketSniffer
OBJS = ARP.o Ethernet.o  IP.o TCP_UDP.o  WSPCAP.o GOhdr.o simpleCLpacketSniffer.o 

default: all

%.o: %.c
	@echo "compiling... " $<
	@$(CC) -c $(CFLAGS) -o $@ $<

$(OUTPUT): $(OBJS)
	@echo "Linking " $@
	$(CC) $(OBJS) $(LFLAGS) -o $@

all: $(OUTPUT)

clean:
	@rm -f $(OBJS)
	@rm -f $(OUTPUT)
	@echo Clean Complete.

.PHONY: clean all
