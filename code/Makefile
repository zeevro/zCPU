SRC=$(wildcard *.asm3)
BIN=$(SRC:.asm3=.image)

all: $(BIN)

%.image: %.asm3
	./asm3.py -o $@ $^

clean:
	$(RM) $(BIN)
