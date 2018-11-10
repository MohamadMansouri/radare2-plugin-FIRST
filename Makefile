CFLAGS=-I/usr/include/libr -I/usr/include
# $(shell pkg-config --cflags r_core)
LDFLAGS=$(shell pkg-config --libs r_core) $(shell curl-config --libs)
PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)
LIBEXT=$(shell r2 -H LIBEXT)
PLUGNAME=first
TARGET=$(PLUGNAME).$(LIBEXT)

all:
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -fPIC utils.c first.c jsmn.c -o first.$(LIBEXT)
	$(MAKE) install


install:
	mkdir -p $(PLUGDIR)
	rm -rf $(PLUGDIR)/$(TARGET)
	cp -rf $(TARGET) $(PLUGDIR)/

uninstall:
	rm -rf $(PLUGDIR)/$(TARGET)

clean:
	rm -rf $(TARGET)
	rm -rf *.o