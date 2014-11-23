CC = gcc
CFLAGS += -g -Wall 
LFLAGS += -lcap
OUTPUT = simpleSniffer
OBJS += simpleCLpacketSniffer.o Ethernet.o GOhdr.o TCP_UDP.o IP.o ARP.o WSPCAP.o

default: all

%.o: %.c
	@echo "Compiling " $<
	@$(CC) -c $(CFLAGS) -o $@ $<
	
$(OUTPUT): $(OBJS)
	@echo "Linking " $@
	@$(CC) $< $(LFLAGS) -o $@

all: $(OUTPUT)

clean:
	@rm -f $(OBJS)
	@rm -f $(OUTPUT)
	@echo Clean complete.

.PHONY: clean all
