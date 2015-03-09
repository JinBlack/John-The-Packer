CC=gcc
CFLAGS=-m32
LDFLAGS=
SOURCES=
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=topack

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) main.c -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm $(EXECUTABLE) $(OBJECTS)
