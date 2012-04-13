Summary: Secure Filesystem
Name: sfs
Version: 0.2
Release: 1
Copyright: GPL
Group: Daemons
Source: sfs-0.2.tgz
BuildRoot: /var/tmp/sfs-root

%changelog
* Fri May 15 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
- BuildRoot'ed

%description 
This is a Secure File System. It provides transparent online compression
on top of any filesystem.

%prep
%setup

%build
rm -rf $RPM_BUILD_ROOT
make -C src

%install
make -C src install INST_ROOT=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%doc doc/* sfs_start sfs_stop
/etc/sfs/
/etc/rc.d/init.d/sfsd
/usr/sbin/sfsd
/usr/bin/sfs_chmod
/usr/bin/sfs_adduser
/usr/bin/sfs_login
/usr/bin/sfs_passwd
/usr/bin/sfs_test
/usr/lib/libsfs.so
