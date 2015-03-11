CC=gcc
CFLAGS=-m32
LDFLAGS=-lm
SOURCES=
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=topack
PACKER=encryptbinary.py

all: $(SOURCES) $(EXECUTABLE) pack
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) main.c -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

pack:
	./$(PACKER) $(EXECUTABLE)

clean:
	rm $(EXECUTABLE) $(OBJECTS)
