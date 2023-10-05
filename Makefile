.POSIX:

OBJS=src/lcws.o src/utils.o
TARGET=lcws.so
INCLUDES=-I includes
CC=clang
CFLAGS=$(INCLUDES) -O3

DISTARGET=disbot
DISINCLUDES=-I /usr/include/json-c/ -ljson-c -lssl -lcrypto
ENDTARGET=endian
ENDINCLUDES=-lssl -lcrypto

INSTALL_PREFIX=/usr/local

.c.o:
	$(CC) $(INCLUDES) -c -o $@ $<

all: $(TARGET) $(DISTARGET) $(ENDTARGET)

$(TARGET): $(OBJS)
	$(CC) $(INCLUDES) -shared $(OBJS) -o $@

##########
## Tests have lcws.so code is statically 
## Built into the tests to ensure that 
## The latest version is built for testing
##########
$(DISTARGET): $(OBJS) examples/discord.c
	$(CC) $(INCLUDES) $(DISINCLUDES) $(OBJS) examples/discord.c -o $@

$(ENDTARGET): $(OBJS) examples/endian.c
	$(CC) $(INCLUDES) $(ENDINCLUDES) $(OBJS) examples/endian.c -o $@

install:
	install -m 755 $(TARGET) $(INSTALL_PREFIX)/lib/liblcws.so.0.1
	install -m 644 includes/lcws.h $(INSTALL_PREFIX)/include/lcws.h
	ln -s $(INSTALL_PREFIX)/lib/liblcws.so.0.1 $(INSTALL_PREFIX)/lib/liblcws.so

uninstall:
	rm $(INSTALL_PREFIX)/lib/liblcws.so.0.1 $(INSTALL_PREFIX)/lib/liblcws.so $(INSTALL_PREFIX)/include/lcws.h

clean:
	rm $(OBJS) $(TARGET) $(DISTARGET) $(ENDTARGET)
