TOOLCHAIN_PREFIX=
CC :=$(TOOLCHAIN_PREFIX)gcc
CPP :=$(TOOLCHAIN_PREFIX)g++
AR :=$(TOOLCHAIN_PREFIX)ar
LD :=$(TOOLCHAIN_PREFIX)ld
RANNLIB := $(TOOLCHAIN_PREFIX)ranlib
LDFLAGS :=  -Wl,-O2,-s -Wl,--as-needed -Xlinker '-rpath=.'
CFLAGS=-O3 -march=x86-64 -mtune=generic  
INCLUDES="../crypto/engine_nix"

LIB=libcpcert.so

SRC_EXEC = get-cpcert.c
SRC_LIB = libcpcert.c
        

all: get-cpcert

$(LIB):$(SRC_LIB)
	$(CC) -o $(LIB) $(SRC_LIB) -shared $(CFLAGS) $(LDFLAGS) -fPIC  -I$(INCLUDES) -L. -l:libgost.so -lz -lzip  
	
get-cpcert: $(LIB)
	$(CC) -o $@ $(SRC_EXEC) $(CFLAGS) $(LDFLAGS) -I$(INCLUDES) -L. -l:libgost.so -l:$<





