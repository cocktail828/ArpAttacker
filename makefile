CC := gcc

OBJECTS := $(patsubst %.c, %.o, $(wildcard *.c))
TARGET := ArpSpoof

CFLAGS += -Wall

ArpSpoof: clean $(OBJECTS)
	$(CC) $(OBJECTS) -o $@

clean:
	rm -rf *.o $(TARGET)
