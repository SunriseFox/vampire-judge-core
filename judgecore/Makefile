IDIR=./src/include
ODIR=obj

CC=g++
CFLAGS=-I$(IDIR) -Wall -Wextra -O2 -pthread
LDFLAGS=-lpthread

DEPS=$(wildcard src/includes/*)

SRC=$(wildcard src/*.cpp)
OBJ=$(patsubst src/%.cpp,$(ODIR)/%.o,$(SRC))

all: compiler judgecore

$(ODIR)/:
	mkdir -p $@

# order-only target $ODIR in case of rebuilding
$(ODIR)/%.o: src/%.cpp $(DEPS) |$(ODIR)/
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean all

clean:
	rm -Iv $(ODIR)/*.o compiler judgecore ||:

compiler: $(OBJ)
	$(CC) -o compiler $(ODIR)/compiler.o $(ODIR)/utils.o $(LDFLAGS)

judgecore: $(OBJ)
	$(CC) -o judgecore $(ODIR)/main.o $(ODIR)/utils.o $(ODIR)/syscall.o $(LDFLAGS)
