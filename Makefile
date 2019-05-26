cc = gcc
CFLAGS += -g
DEPS = $(wildcard *.h)
OBJECTS = inject.c

mane: $(OBJECTS)
	gcc $< $(DEPS)
.PHONY: mane

%.o: %.c
	gcc -c $< -o $@ $(CFLAGS)

clean:
	rm -f ./*.o ./*.h.gch ./.*.*.swp a.out
.PHONY: clean
