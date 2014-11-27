# SimpleCLpacketSniffer Makefile

CC = gcc
CFLAGS += -g -Wall

# add the path to my library code; -L tells the linker where to find it
LFLAGS += -L /home/hagai/git/SimpleSniffer/SimpleCLPacketSniffer/debag/src -lcap

OUTPUT += simpleCLpacketSniffer
OBJS += Ethernet.o IP.o TCP_UDP.o  WSPCAP.o GOhdr.o simpleCLpacketSniffer.o 

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
