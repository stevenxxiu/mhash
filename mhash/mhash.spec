%define prefix   /usr

Summary: Thread-safe hash library
Name: mhash
Version: 0.8.13
Release: 1
Copyright: LGPL
Group: System Environment/Libraries
Source: http://schumann.cx/mhash/dl/%{name}-%{version}.tar.gz
BuildRoot: /tmp/%{name}-%{version}-root
Packager: Germano Rizzo <mano@pluto.linux.it>
URL: http://mhash.sourceforge.net

%description
mhash is a thread-safe hash library, implemented in C, and provides a
uniform interface to a large number of hash algorithms (MD5, SHA-1,
HAVAL, RIPEMD128, RIPEMD160, TIGER, GOST). These algorithms can be 
used to compute checksums, message digests, and other signatures.
The HMAC support implements the basics for message authentication, 
following RFC 2104.

%package devel
Summary: Header files and libraries for developing apps which will use mhash
Group: Development/Libraries
Requires: mhash

%description devel
The mhash-devel package contains the header files and libraries needed
to develop programs that use the mhash library.

Install the mhash-devel package if you want to develop applications that
will use the mhash library.

%changelog
* Fri Feb 01 2002 Germano Rizzo <mano@pluto.linux.it>
- Built version 0.8.13 basing on Kyle Wheeler's SPEC file
* Sat Jun 10 2000 Kyle Wheeler <memoryhole@penguinpowered.com>
- Updated for version 0.8.1
* Wed Feb 9 2000 Clinton Work <clinton@scripty.com>
- Created a new spec file for version 0.6.1
- Created both a shared library and devel packages

%prep
%setup

%build
CFLAGS="${RPM_OPT_FLAGS}"
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%{prefix}
make

%install
rm -rf $RPM_BUILD_ROOT
make prefix=$RPM_BUILD_ROOT%{prefix} install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{prefix}/lib/libmhash.so.*

%files devel
%defattr(-, root, root)
%doc AUTHORS COPYING INSTALL ChangeLog NEWS README TODO
%doc doc/example.c doc/md5-rfc1321.txt doc/mhash.html doc/skid2-authentication
%{prefix}/man/man3/mhash.3.gz
%{prefix}/lib/*.a
%{prefix}/lib/*.la
%{prefix}/lib/*.so
%{prefix}/include/*.h


