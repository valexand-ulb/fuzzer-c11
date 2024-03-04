CC = gcc
CFLAGS = -g

# Get all .c files in the current directory
SOURCES := $(wildcard *.c)

# Derive the list of headers from the source files
HEADERS := $(wildcard *.h)

# Derive the list of executables from the source files
EXECUTABLE := fuzzer

# Rule to compile all .c files into an executable
$(EXECUTABLE): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) -o $(EXECUTABLE)

# Clean rule
clean: rm -f $(EXECUTABLE)

