CFLAGS=-I/usr/include/libr -I/usr/include
# $(shell pkg-config --cflags r_core)
LDFLAGS=$(shell pkg-config --libs r_core) $(shell curl-config --libs)
PLUGDIR=$(shell r2 -H R2_USER_PLUGINS)
LIBEXT=$(shell r2 -H LIBEXT)
PLUGNAME=first
TARGET=$(PLUGNAME).$(LIBEXT)


# ifndef VERBOSE
# .SILENT:
# endif


all:
	$(CC) $(CFLAGS) $(LDFLAGS) -g -O3 -shared -fPIC -Wno-discarded-qualifiers utils.c first.c jsmn.c ini.c -o first.$(LIBEXT)
	$(MAKE) install

.PHONY : install
install:
	mkdir -p $(HOME)/.config/first
	mkdir -p $(HOME)/.config/first/db
	cp -rf first.config $(HOME)/.config/first/  
	mkdir -p $(PLUGDIR)
	rm -rf $(PLUGDIR)/$(TARGET)
	cp -rf $(TARGET) $(PLUGDIR)/

.PHONY : uninstall
uninstall:
	rm -rf $(PLUGDIR)/$(TARGET)
	rm -rf $(HOME)/.config/first

.PHONY : clean
clean:
	rm -rf $(TARGET)
