CFLAGS ?= -O2
CPPFLAGS ?= -I/usr/local/include
BUILD_CFLAGS = -std=gnu11 -Wall -Wextra -fPIC

all: ha-auth.so pw

ha-auth.so: ha_auth.c pbkdf2.c pbkdf2.h
	$(CC) $(CPPFLAGS) $(BUILD_CFLAGS) $(CFLAGS) -shared -o $@ ha_auth.c pbkdf2.c $(LDFLAGS) -lcurl -lcrypto

pw: pw.c pbkdf2.c pbkdf2.h
	$(CC) $(CPPFLAGS) $(BUILD_CFLAGS) $(CFLAGS) -o $@ pw.c pbkdf2.c $(LDFLAGS) -lcrypto

install: all
	install -D -m 0644 ha-auth.so $(DESTDIR)/usr/share/mosquitto/ha-auth.so
	install -D -m 0755 pw $(DESTDIR)/usr/local/bin/pw

clean:
	rm -f ha-auth.so pw

.PHONY: all install clean
