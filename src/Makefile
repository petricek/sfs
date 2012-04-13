# Makefile for sfs
# Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>

ROOTDIR		= $(INST_ROOT)
ETCDIR		= $(ROOTDIR)/etc
USRDIR		= $(ROOTDIR)/usr
BINDIR		= $(USRDIR)/bin
SBINDIR		= $(USRDIR)/sbin
LIBDIR		= $(USRDIR)/lib
RCDDIR		= $(ETCDIR)/rc.d/init.d
SFSDIR		= $(ETCDIR)/sfs

CC	= gcc
CFLAGS	= -pedantic -W -Wall -g
# -Wtraditional -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wnested-externs
# -Wredundant-decls -Wid-clash-len
INSTALL	= install

LIBSFS_O	= read.o write.o fchmod.o open.o close.o sfs_debug.o sfs_lib.o mmap.o dup.o
SFSD_O		= sfsd.o sfs_lib.o sfs_misc.o sfs_debug.o sfsd_req.o sfs_secure.o blowfish.o mrsa.o
SFSC_O		= sfs_client.o sfs_debug.o
LOGIN_O		= sfs_login.o sfs_debug.o sfs_misc.o blowfish.o mrsa.o sfs_secure.o sfs_lib.o
TEST_O		= sfs_test.o
PASSWD_O	= sfs_passwd.o sfs_secure.o sfs_debug.o blowfish.o mrsa.o sfs_misc.o
ADDUSER_O	= sfs_adduser.o sfs_secure.o sfs_debug.o blowfish.o mrsa.o sfs_misc.o sfs_lib.o
CHMOD_O		= sfs_chmod.o sfs_lib.o sfs_debug.o

all: sfsd sfs_chmod libsfs sfs_login sfs_passwd sfs_adduser sfs_test

install: FORCE
	mkdir -p $(RCDDIR)
	mkdir -p $(USRDIR)
	mkdir -p $(BINDIR)
	mkdir -p $(SBINDIR)
	mkdir -p $(LIBDIR)
	mkdir -p $(SFSDIR)
	$(INSTALL) -o root -g root -m 0755 sfsd $(SBINDIR)
	$(INSTALL) -o root -g root -m 0755 sfs_chmod $(BINDIR)
	$(INSTALL) -o root -g root -m 0755 sfs_adduser $(BINDIR)
	$(INSTALL) -o root -g root -m 4755 sfs_passwd $(BINDIR)
	$(INSTALL) -o root -g root -m 4755 sfs_login $(BINDIR)
	$(INSTALL) -o root -g root -m 0755 sfs_test $(BINDIR)
	$(INSTALL) -o root -g root -m 0644 libsfs.so $(LIBDIR)
	$(INSTALL) -o root -g root -m 0755 sfsd.init $(RCDDIR)/sfsd

sfsd: $(SFSD_O)
	$(CC) $(CFLAGS) -o sfsd $(SFSD_O)

libsfs: $(LIBSFS_O)
	$(CC) $(CFLAGS) -o libsfs.so $(LIBSFS_O) -shared

sfs_test: $(TEST_O)
	$(CC) $(CFLAGS) -o sfs_test $(TEST_O)

sfs_client: $(SFSC_O)
	$(CC) $(CFLAGS) -o sfs_client $(SFSC_O)

sfs_login: $(LOGIN_O)
	$(CC) $(CFLAGS) -o sfs_login $(LOGIN_O)

sfs_passwd: $(PASSWD_O)
	$(CC) $(CFLAGS) -o sfs_passwd $(PASSWD_O)

sfs_adduser: $(ADDUSER_O)
	$(CC) $(CFLAGS) -o sfs_adduser $(ADDUSER_O)

sfs_chmod: $(CHMOD_O)
	$(CC) $(CFLAGS) -o sfs_chmod $(CHMOD_O)

main: *.cc *.c *.h
	$(CC) -g -Wall -W -o main main.cc sfs_secure.c mrsa.c blowfish.c sfs_debug.c sfs_misc.c sfs_lib.c

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

restart: stop start

start: FORCE
	./sfsd

stop: FORCE
	killall -15 sfsd

chown: FORCE
	chown root sfsd
	chmod u+s sfsd
	chown root sfs_login
	chmod u+s sfs_login
	chown root sfs_passwd
	chmod u+s sfs_passwd

clean: FORCE
	rm -rf core *.o sfsd libsfs.so sfs_test sfs_client sfs_login \
		sfs_passwd temp temporary main sfs_chmod sfs_adduser

FORCE:
