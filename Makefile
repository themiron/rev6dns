#CROSS=mipsel-uclibc-
CC=$(CROSS)gcc
LD=$(CROSS)ld
AR=$(CROSS)ar
RANLIB=$(CROSS)ranlib

CCFLAGS+=-O2 -Wall -I. -Wno-pointer-sign -fomit-frame-pointer
LDFLAGS+=-s
LIBS=

PACKAGE=rev6dns
OBJS=$(PACKAGE).o

all: $(PACKAGE)

$(PACKAGE): $(PACKAGE).o $(LIBS)
	$(CC) $(CCFLAGS) $(LDFLAGS) $(OBJS) -o $(PACKAGE) $(LIBS)

%.o: %.c
	$(CC) $(CCFLAGS) -c $<

clean:
	rm *.o $(PACKAGE)
