# configure options
#
# Some can be overriden on rpmbuild commandline with:
# rpmbuild --define 'variable value'
#

####################### Quagga configure options #########################
# with-feature options
%{!?with_snmp:		%define with_snmp	1 }
%{!?with_vtysh:		%define	with_vtysh	1 }
%{!?with_ospf_te:	%define	with_ospf_te	1 }
%{!?with_nssa:		%define	with_nssa	1 }
%{!?with_opaque_lsa:	%define	with_opaque_lsa 1 }
%{!?with_tcp_zebra:	%define	with_tcp_zebra	0 }
%{!?with_vtysh:		%define	with_vtysh	1 }
%{!?with_pam:		%define	with_pam	1 }
%{!?with_ipv6:		%define	with_ipv6	1 }
%{!?with_ospfclient:	%define	with_ospfclient 1 }
%{!?with_ospfapi:	%define	with_ospfapi	1 }
%{!?with_irdp:		%define	with_irdp	1 }
%{!?with_rtadv:		%define	with_rtadv	1 }
%{!?with_isisd:		%define	with_isisd	1 }
%{!?with_shared:	%define	with_shared	1 }
%{!?with_multipath:	%define	with_multipath	64 }
%{!?quagga_user:	%define	quagga_user	quagga }
%{!?vty_group:		%define	vty_group	quaggavty }

# path defines
%define		_sysconfdir	/etc/quagga
%define		zeb_src		%{_builddir}/%{name}-%{version}
%define		zeb_rh_src	%{zeb_src}/redhat
%define		zeb_docs	%{zeb_src}/doc

# defines for configure
%define		_libexecdir	%{_exec_prefix}/libexec/quagga
%define		_libdir		%{_exec_prefix}/%{_lib}/quagga
%define		_includedir	%{_prefix}/include
%define		_localstatedir	/var/run/quagga
############################################################################

####################### distro specific tweaks #############################
# default distro. Override with rpmbuild -D "dist XXX" 
%{expand: %%define default_dist %(rpm -q --qf 'fc%%{VERSION}' fedora-release | grep -v 'not installed')}
%{!?dist:		%define		dist	%{default_dist}}

# as distros change packages we depend on, our Requires have to change, sadly.
%define quagga_buildreqs texinfo tetex autoconf pam-devel
%define quagga_buildreqs %{quagga_buildreqs} patch libcap-devel

# FC4 and 5 split texi2html out of tetex package.
%if "%dist" != "fc2" || "%dist" != "fc3"
%define  quagga_buildreqs %{quagga_buildreqs} texi2html
%endif

# pam_stack is deprecated in FC5
# default to pam_stack, default should be changed later.
%if "%dist" == "fc4" || "%dist" == "fc3"
%define	quagga_pam_source quagga.pam.stack
%else
%define	quagga_pam_source quagga.pam
%endif
############################################################################


# misc internal defines
%{!?quagga_uid:		%define         quagga_uid      92 }
%{!?quagga_gid:		%define         quagga_gid      92 }
%define		daemon_list	zebra ripd ospfd bgpd

%if %{with_ipv6}
%define		daemonv6_list	ripngd ospf6d
%else
%define		daemonv6_list	""
%endif

%if %{with_isisd}
%define		daemon_other	isisd
%else
%define		daemon_other	""
%endif

%define		all_daemons	%{daemon_list} %{daemonv6_list} %{daemon_other} watchquagga

# allow build dir to be kept
%{!?keep_build:		%define		keep_build	0 }

#release sub-revision (the two digits after the CONFDATE)
%{!?release_rev:	%define		release_rev	01 }

Summary: Routing daemon
Name:		quagga
Version:	0.99.20
Release:	20140403%{release_rev}
License:	GPL
Group: System Environment/Daemons
Source0:	http://www.quagga.net/snapshots/cvs/%{name}-%{version}.tar.gz
URL:		http://www.quagga.net
%if %{with_snmp}
BuildRequires:	net-snmp-devel
Prereq:		net-snmp
%endif
%if %{with_vtysh}
BuildRequires:	readline readline-devel ncurses ncurses-devel
Prereq:		ncurses
%endif
BuildRequires:	texinfo tetex autoconf pam-devel patch libcap-devel tetex
# Initscripts > 5.60 is required for IPv6 support
Prereq:		initscripts >= 5.60
Prereq:		ncurses pam
Prereq:		/sbin/install-info
Provides:	routingdaemon
BuildRoot:	%{_tmppath}/%{name}-%{version}-root
Obsoletes:	bird gated mrt zebra

%description
Quagga is a free software that manages TCP/IP based routing
protocol. It takes multi-server and multi-thread approach to resolve
the current complexity of the Internet.

Quagga supports BGP4, BGP4+, OSPFv2, OSPFv3, RIPv1, RIPv2, and RIPng.

Quagga is intended to be used as a Route Server and a Route Reflector. It is
not a toolkit, it provides full routing power under a new architecture.
Quagga by design has a process for each protocol.

Quagga is a fork of GNU Zebra.

%package contrib
Summary: contrib tools for quagga
Group: System Environment/Daemons

%description contrib
Contributed/3rd party tools which may be of use with quagga.

%package devel
Summary: Header and object files for quagga development
Group: System Environment/Daemons

%description devel
The quagga-devel package contains the header and object files neccessary for
developing OSPF-API and quagga applications.

%prep
%setup  -q

%build

# For standard gcc verbosity, uncomment these lines:
#CFLAGS="%{optflags} -Wall -Wsign-compare -Wpointer-arith"
#CFLAGS="${CFLAGS} -Wbad-function-cast -Wwrite-strings"

# For ultra gcc verbosity, uncomment these lines also:
#CFLAGS="${CFLAGS} -W -Wcast-qual -Wstrict-prototypes"
#CFLAGS="${CFLAGS} -Wmissing-declarations -Wmissing-noreturn"
#CFLAGS="${CFLAGS} -Wmissing-format-attribute -Wunreachable-code"
#CFLAGS="${CFLAGS} -Wpacked -Wpadded"

%configure \
%if !%{with_shared}
	--disable-shared \
%endif
%if %{with_ipv6}
	--enable-ipv6 \
%endif
%if %{with_snmp}
	--enable-snmp \
%endif
%if %{with_multipath}
	--enable-multipath=%{with_multipath} \
%endif
%if %{with_tcp_zebra}
	--enable-tcp-zebra \
%endif
%if %{with_nssa}
	--enable-nssa \
%endif
%if %{with_opaque_lsa}
	--enable-opaque-lsa \
%endif
%if %{with_ospf_te}
	--enable-ospf-te \
%endif
%if %{with_vtysh}
	--enable-vtysh \
%endif
%if %{with_ospfclient}
	--enable-ospfclient=yes \
%else
	--enable-ospfclient=no\
%endif
%if %{with_ospfapi}
	--enable-ospfapi=yes \
%else
	--enable-ospfapi=no \
%endif
%if %{with_irdp}
	--enable-irdp=yes \
%else
	--enable-irdp=no \
%endif
%if %{with_rtadv}
	--enable-rtadv=yes \
%else
	--enable-rtadv=no \
%endif
%if %{with_isisd}
	--enable-isisd \
%else
	--disable-isisd \
%endif
%if %{with_pam}
	--with-libpam \
%endif
%if %quagga_user
	--enable-user=%quagga_user \
	--enable-group=%quagga_user \
%endif
%if %vty_group
	--enable-vty-group=%vty_group \
%endif
--enable-netlink --enable-gcc-rdynamic

make %{?_smp_mflags} MAKEINFO="makeinfo --no-split"

pushd doc
texi2html -number quagga.texi
popd

%install
rm -rf $RPM_BUILD_ROOT

install -d $RPM_BUILD_ROOT/etc/{rc.d/init.d,sysconfig,logrotate.d,pam.d} \
	$RPM_BUILD_ROOT/var/log/quagga $RPM_BUILD_ROOT%{_infodir}

make install \
	DESTDIR=$RPM_BUILD_ROOT

# Remove this file, as it is uninstalled and causes errors when building on RH9
rm -rf $RPM_BUILD_ROOT/usr/share/info/dir

# install etc sources
for daemon in %{all_daemons} ; do
	if [ x"${daemon}" != x"" ] ; then
		install %{zeb_rh_src}/${daemon}.init \
			$RPM_BUILD_ROOT/etc/rc.d/init.d/${daemon}
	fi
done
install -m644 %{zeb_rh_src}/%{quagga_pam_source} \
	$RPM_BUILD_ROOT/etc/pam.d/quagga
install -m644 %{zeb_rh_src}/quagga.logrotate \
	$RPM_BUILD_ROOT/etc/logrotate.d/quagga
install -m644 %{zeb_rh_src}/quagga.sysconfig \
	$RPM_BUILD_ROOT/etc/sysconfig/quagga
install -d -m750  $RPM_BUILD_ROOT/var/run/quagga

%pre
# add vty_group
%if %vty_group
if getent group %vty_group > /dev/null ; then : ; else \
 /usr/sbin/groupadd -r %vty_group > /dev/null || : ; fi
%endif

# add quagga user and group
%if %quagga_user
# Ensure that quagga_gid gets correctly allocated
if getent group %quagga_user >/dev/null; then : ; else \
 /usr/sbin/groupadd -g %quagga_gid %quagga_user > /dev/null || : ; \
fi
if getent passwd %quagga_user >/dev/null ; then : ; else \
 /usr/sbin/useradd  -u %quagga_uid -g %quagga_gid \
  -M -r -s /sbin/nologin -c "Quagga routing suite" \
  -d %_localstatedir %quagga_user 2> /dev/null || : ; \
fi
%endif

%post
# zebra_spec_add_service <service name> <port/proto> <comment>
# e.g. zebra_spec_add_service zebrasrv 2600/tcp "zebra service"

zebra_spec_add_service ()
{
  # Add port /etc/services entry if it isn't already there 
  if [ -f /etc/services ] && \
      ! %__sed -e 's/#.*$//' /etc/services | %__grep -wq $1 ; then
    echo "$1		$2			# $3"  >> /etc/services
  fi
}

zebra_spec_add_service zebrasrv 2600/tcp "zebra service"
zebra_spec_add_service zebra    2601/tcp "zebra vty"
zebra_spec_add_service ripd     2602/tcp "RIPd vty"
%if %{with_ipv6}
zebra_spec_add_service ripngd   2603/tcp "RIPngd vty"
%endif
zebra_spec_add_service ospfd    2604/tcp "OSPFd vty"
zebra_spec_add_service bgpd     2605/tcp "BGPd vty"
%if %{with_ipv6}
zebra_spec_add_service ospf6d   2606/tcp "OSPF6d vty"
%endif
%if %{with_ospfapi}
zebra_spec_add_service ospfapi  2607/tcp "OSPF-API"
%endif
%if %{with_isisd}
zebra_spec_add_service isisd    2608/tcp "ISISd vty"
%endif

for daemon in %daemon_list ; do
	/sbin/chkconfig --add ${daemon}
done

/sbin/install-info %{_infodir}/quagga.info.gz %{_infodir}/dir

# Create dummy files if they don't exist so basic functions can be used.
if [ ! -e %{_sysconfdir}/zebra.conf ]; then
	echo "hostname `hostname`" > %{_sysconfdir}/zebra.conf
%if %{quagga_user}
	chown %quagga_user:%quagga_user %{_sysconfdir}/zebra.conf
%endif
	chmod 640 %{_sysconfdir}/zebra.conf
fi
if [ ! -e %{_sysconfdir}/vtysh.conf ]; then
	touch %{_sysconfdir}/vtysh.conf
	chmod 640 %{_sysconfdir}/vtysh.conf
fi

%postun
if [ "$1" -ge 1 ]; then
	# Find out which daemons need to be restarted.
	for daemon in %all_daemons ; do
		if [ -f /var/lock/subsys/$daemon ]; then
			eval restart_$daemon=yes
		else
			eval restart_$daemon=no
		fi
	done
	# Rename restart flags for daemons handled specially.
	running_zebra="$restart_zebra"
	restart_zebra=no
	running_watchquagga="$restart_watchquagga"
	restart_watchquagga=no
	# Stop watchquagga first.
	[ "$running_watchquagga" = yes ] && \
		/etc/rc.d/init.d/watchquagga stop >/dev/null 2>&1
	# Stop all daemons other than zebra and watchquagga.
	for daemon in %all_daemons ; do
		eval restart=\$restart_${daemon}
		[ "$restart" = yes ] && \
			/etc/rc.d/init.d/$daemon stop >/dev/null 2>&1
	done
	# Restart zebra.
	[ "$running_zebra" = yes ] && \
		/etc/rc.d/init.d/zebra restart >/dev/null 2>&1
	# Start all daemons other than zebra and watchquagga.
	for daemon in %all_daemons ; do
		eval restart=\$restart_${daemon}
		[ "$restart" = yes ] && \
			/etc/rc.d/init.d/$daemon start >/dev/null 2>&1
	done
	# Start watchquagga last.
	# Avoid postun scriptlet error if watchquagga is not running. 
	[ "$running_watchquagga" = yes ] && \
		/etc/rc.d/init.d/watchquagga start >/dev/null 2>&1 || :
fi
/sbin/install-info --delete %{_infodir}/quagga.info.gz %{_infodir}/dir

%preun
if [ "$1" = "0" ]; then
	for daemon in %all_daemons ; do
		/etc/rc.d/init.d/${daemon} stop  >/dev/null 2>&1
		/sbin/chkconfig --del ${daemon}
	done
	/sbin/install-info --delete %{_infodir}/quagga.info.gz %{_infodir}/dir
fi

%clean
%if !%{keep_build}
rm -rf $RPM_BUILD_ROOT
%endif

%files
%defattr(-,root,root)
%doc */*.sample* AUTHORS COPYING
%doc doc/quagga.html
%doc doc/mpls
%doc ChangeLog INSTALL NEWS README REPORTING-BUGS SERVICES TODO
%if %{quagga_user}
%dir %attr(751,%quagga_user,%quagga_user) %{_sysconfdir}
%dir %attr(750,%quagga_user,%quagga_user) /var/log/quagga 
%dir %attr(751,%quagga_user,%quagga_user) /var/run/quagga
%else
%dir %attr(750,root,root) %{_sysconfdir}
%dir %attr(750,root,root) /var/log/quagga
%dir %attr(755,root,root) /usr/share/info
%dir %attr(750,root,root) /var/run/quagga
%endif
%if %{vty_group}
%attr(750,%quagga_user,%vty_group) %{_sysconfdir}/vtysh.conf.sample
%endif
%{_infodir}/*info*
%{_mandir}/man*/*
%{_sbindir}/zebra
%{_sbindir}/ospfd
%{_sbindir}/ripd
%{_sbindir}/bgpd
%{_sbindir}/watchquagga
%if %{with_ipv6}
%{_sbindir}/ripngd
%{_sbindir}/ospf6d
%endif
%if %{with_isisd}
%{_sbindir}/isisd
%endif
%dir %attr(755,root,root) %{_libdir}
%if %{with_shared}
%dir %{_libdir}
%{_libdir}/lib*.so
%{_libdir}/lib*.so.*
%endif
%if %{with_vtysh}
%{_bindir}/*
%endif
%config /etc/quagga/[!v]*
%config /etc/rc.d/init.d/*
%config(noreplace) /etc/sysconfig/quagga
%config(noreplace) /etc/pam.d/quagga
%config(noreplace) %attr(640,root,root) /etc/logrotate.d/*

%files contrib
%defattr(-,root,root)
%doc tools

%files devel
%defattr(-,root,root)
%if %{with_ospfclient}
%{_sbindir}/ospfclient
%endif
%{_libdir}/*.a
%{_libdir}/*.la
%dir %attr(755,root,root) %{_includedir}/%{name}
%{_includedir}/%name/*.h
%dir %attr(755,root,root) %{_includedir}/%{name}/ospfd
%{_includedir}/%name/ospfd/*.h
%if %{with_ospfapi}
%dir %attr(755,root,root) %{_includedir}/%{name}/ospfapi
%{_includedir}/%name/ospfapi/*.h
%endif

%changelog
* Thu Sep 12 2005 Paul Jakma <paul@dishone.st>
- Steal some changes from Fedora spec file:
- Add with_rtadv variable
- Test for groups/users with getent before group/user adding
- Readline need not be an explicit prerequisite
- install-info delete should be postun, not preun

* Wed Jan 12 2005 Andrew J. Schorr <ajschorr@alumni.princeton.edu>
- on package upgrade, implement careful, phased restart logic
- use gcc -rdynamic flag when linking for better backtraces

* Wed Dec 22 2004 Andrew J. Schorr <ajschorr@alumni.princeton.edu>
- daemonv6_list should contain only IPv6 daemons

* Wed Dec 22 2004 Andrew J. Schorr <ajschorr@alumni.princeton.edu>
- watchquagga added
- on upgrade, all daemons should be condrestart'ed
- on removal, all daemons should be stopped

* Mon Nov 08 2004 Paul Jakma <paul@dishone.st>
- Use makeinfo --html to generate quagga.html

* Sun Nov 07 2004 Paul Jakma <paul@dishone.st>
- Fix with_ipv6 set to 0 build

* Sat Oct 23 2004 Paul Jakma <paul@dishone.st>
- Update to 0.97.2

* Sat Oct 23 2004 Andrew J. Schorr <aschorr@telemetry-investments.com>
- Make directories be owned by the packages concerned
- Update logrotate scripts to use correct path to killall and use pid files

* Fri Oct 08 2004 Paul Jakma <paul@dishone.st>
- Update to 0.97.0

* Wed Sep 15 2004 Paul Jakma <paul@dishone.st>
- build snmp support by default
- build irdp support
- build with shared libs
- devel subpackage for archives and headers

* Thu Jan 08 2004 Paul Jakma <paul@dishone.st>
- updated sysconfig files to specify local dir
- added ospf_dump.c crash quick fix patch
- added ospfd persistent interface configuration patch

* Tue Dec 30 2003 Paul Jakma <paul@dishone.st>
- sync to CVS
- integrate RH sysconfig patch to specify daemon options (RH)
- default to have vty listen only to 127.1 (RH)
- add user with fixed UID/GID (RH)
- create user with shell /sbin/nologin rather than /bin/false (RH)
- stop daemons on uninstall (RH)
- delete info file on %preun, not %postun to avoid deletion on upgrade. (RH)
- isisd added
- cleanup tasks carried out for every daemon

* Sun Nov 2 2003 Paul Jakma <paul@dishone.st>
- Fix -devel package to include all files
- Sync to 0.96.4

* Tue Aug 12 2003 Paul Jakma <paul@dishone.st>
- Renamed to Quagga
- Sync to Quagga release 0.96

* Tue Mar 20 2003 Paul Jakma <paul@dishone.st>
- zebra privileges support

* Mon Mar 18 2003 Paul Jakma <paul@dishone.st>
- Fix mem leak in 'show thread cpu'
- Ralph Keller's OSPF-API
- Amir: Fix configure.ac for net-snmp

* Sat Mar 1 2003 Paul Jakma <paul@dishone.st>
- ospfd IOS prefix to interface matching for 'network' statement
- temporary fix for PtP and IPv6
- sync to zebra.org CVS

* Mon Jan 20 2003 Paul Jakma <paul@dishone.st>
- update to latest cvs
- Yon's "show thread cpu" patch - 17217
- walk up tree - 17218
- ospfd NSSA fixes - 16681
- ospfd nsm fixes - 16824
- ospfd OLSA fixes and new feature - 16823 
- KAME and ifindex fixes - 16525
- spec file changes to allow redhat files to be in tree

* Sat Dec 28 2002 Alexander Hoogerhuis <alexh@ihatent.com>
- Added conditionals for building with(out) IPv6, vtysh, RIP, BGP
- Fixed up some build requirements (patch)
- Added conditional build requirements for vtysh / snmp
- Added conditional to %files for %_bindir depending on vtysh

* Mon Nov 11 2002 Paul Jakma <paulj@alphyra.ie>
- update to latest CVS
- add Greg Troxel's md5 buffer copy/dup fix
- add RIPv1 fix
- add Frank's multicast flag fix

* Wed Oct 09 2002 Paul Jakma <paulj@alphyra.ie>
- update to latest CVS
- timestamped crypt_seqnum patch
- oi->on_write_q fix

* Mon Sep 30 2002 Paul Jakma <paulj@alphyra.ie>
- update to latest CVS
- add vtysh 'write-config (integrated|daemon)' patch
- always 'make rebuild' in vtysh/ to catch new commands

* Fri Sep 13 2002 Paul Jakma <paulj@alphyra.ie>
- update to 0.93b

* Wed Sep 11 2002 Paul Jakma <paulj@alphyra.ie>
- update to latest CVS
- add "/sbin/ip route flush proto zebra" to zebra RH init on startup

* Sat Aug 24 2002 Paul Jakma <paulj@alphyra.ie>
- update to current CVS
- add OSPF point to multipoint patch
- add OSPF bugfixes
- add BGP hash optimisation patch

* Fri Jun 14 2002 Paul Jakma <paulj@alphyra.ie>
- update to 0.93-pre1 / CVS
- add link state detection support
- add generic PtP and RFC3021 support
- various bug fixes

* Thu Aug 09 2001 Elliot Lee <sopwith@redhat.com> 0.91a-6
- Fix bug #51336

* Wed Aug  1 2001 Trond Eivind Glomsr�d <teg@redhat.com> 0.91a-5
- Use generic initscript strings instead of initscript specific
  ( "Starting foo: " -> "Starting $prog:" )

* Fri Jul 27 2001 Elliot Lee <sopwith@redhat.com> 0.91a-4
- Bump the release when rebuilding into the dist.

* Tue Feb  6 2001 Tim Powers <timp@redhat.com>
- built for Powertools

* Sun Feb  4 2001 Pekka Savola <pekkas@netcore.fi> 
- Hacked up from PLD Linux 0.90-1, Mandrake 0.90-1mdk and one from zebra.org.
- Update to 0.91a
- Very heavy modifications to init.d/*, .spec, pam, i18n, logrotate, etc.
- Should be quite Red Hat'isque now.
