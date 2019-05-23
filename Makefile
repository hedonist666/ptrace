cc = gcc
CFLAGS += -g
DEPS = $(wildcard *.h)
OBJECTS = 2.o

mane: $(OBJECTS)
	gcc $< $(DEPS)
.PHONY: mane

%.o: %.c
	gcc -c $< -o $@ $(CFLAGS)

clean:
	rm -f ./*.o ./*.h.gch ./.*.*.swp a.out
.PHONY: clean
