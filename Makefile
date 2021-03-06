
CC := gcc
CFLAGS := -O2 -Wall -Wextra

all: tinyip

tinyip: main.o arp.o ip.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

clean:
	@rm -f *.o tinyip
