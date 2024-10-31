# Makefile for BCC-based BPF program

# Compiler and flags
CC = clang
CFLAGS = -g -O2 -Wall -I/usr/include/bcc/ -I/usr/include/x86_64-linux-gnu/bcc/ -I/usr/include/linux -I/usr/include
LDFLAGS = -lbcc

# Source and target files
SRC = execsnoop.c
TARGET = execsnoop

# Build rule
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Clean rule
clean:
	rm -f $(TARGET)

# Run rule
run: $(TARGET)
	./$(TARGET)

# Install BCC dependencies
install:
	sudo apt-get update
	sudo apt-get install -y bpfcc-tools libbpfcc-dev

# Uninstall BCC dependencies
uninstall:
	sudo apt-get remove -y bpfcc-tools libbpfcc-dev