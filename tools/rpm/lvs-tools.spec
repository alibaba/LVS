Name:    lvs-tools
Version: 1.0.0 
Release: %(echo $RELEASE)%{?dist}
Summary: tools for manage lvs, include keepalived, ipvsadm and quagga
Group: Taobao/Common
URL: %{_svn_path} 
%define _prefix /usr
%define _sbindir_sys /sbin
Source:        %{name}-%{version}.tar.gz
License:       GPL
BuildRequires: kernel, kernel-devel, kernel-headers
BuildRequires: openssl-devel
BuildRequires: libnl-devel
Requires: libnl
#BuildRoot:     %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
SVN URL: %{_svn_path} 
revision: %{_svn_revision}
LVS Tools include ipvsadm, keepalived and quagga;

Keepalived:
The main goal of the keepalived project is to add a strong end robust keepalive
facility to the Linux Virtual Server project.
This project is written in C with multilayer TCP/IP stack checks.
Keepalived implements a framework based on three family checks:
Layer3, Layer4 & Layer5.
This framework gives the daemon the ability of checking a LVS server pool states.
When one of the server of the LVS server pool is down, keepalived informs the linux
kernel via a setsockopt call to remove this server entrie from the LVS topology.
In addition keepalived implements a VRRPv2 stack to handle director failover.
So in short keepalived is a userspace daemon for LVS cluster nodes healthchecks
and LVS directors failover.

Ipvsadm:
ipvsadm is a utility to administer the IP Virtual Server services
offered by the latest Linux kernel 2.6.x.

Quagga:
Quagga is a routing software suite, providing implementations of OSPFv2, OSPFv3, RIP v1 and v2, RIPng and BGP-4 for Unix platforms, particularly FreeBSD, Linux, Solaris and NetBSD. Quagga is a fork of GNU Zebra which was developed by Kunihiro Ishiguro. The Quagga tree aims to build a more involved community around Quagga than the current centralised model of GNU Zebra.

%define __arch_install_post %{nil}

#%prep
#%setup -q

%build
cd $OLDPWD/../keepalived/
./configure --with-kernel-dir="/lib/modules/`uname -r`/build"
make
cd ../ipvsadm/
make
cd ../quagga/
./configure --disable-ripd --disable-ripngd --disable-bgpd --disable-watchquagga --disable-doc  --enable-user=root --enable-vty-group=root --enable-group=root --enable-zebra --localstatedir=/var/run/quagga
make

%install
[ "%{buildroot}" != / ] && rm -rf %{buildroot}
cd $OLDPWD/../keepalived/
%makeinstall
cd ../ipvsadm/
%makeinstall
cd ../quagga/
%makeinstall
mkdir -p %{buildroot}/var/run/quagga
mkdir -p %{buildroot}/var/log/quagga

%post
/sbin/chkconfig --add ipvsadm
/sbin/chkconfig --add keepalived
exit 0

%preun
/sbin/chkconfig --del ipvsadm
/sbin/chkconfig --del keepalived
exit 0

%postun
rm -rf /var/run/quagga
rm -rf /var/log/quagga
exit 0

%clean
[ "%{buildroot}" != / ] && rm -rf %{buildroot}

%files
#cd keepalived/
%defattr(-,root,root)
# /usr/
%{_bindir}/genhash
%{_sbindir}/keepalived
#%{_initrddir}/keepalived
%config(noreplace) %{_sysconfdir}/sysconfig/keepalived
%dir %{_sysconfdir}/keepalived/
%config(noreplace) %{_sysconfdir}/keepalived/*
%doc %{_mandir}/man?/*
#%doc %{_prefix}/{AUTHOR,CONTRIBUTORS,TODO,COPYING,README,VERSION,ChangeLog}
#%doc /usr/share/doc/keepalived.conf.SYNOPSIS 
#%doc /usr/share/doc/samples/

#%defattr(-,root,root)
#%doc %{_prefix}/README
#%config %{_sysconfdir}/rc.d/init.d/ipvsadm
%{_sbindir_sys}/ipvsadm*
%doc %{_prefix}/man/man8/ipvsadm*

%defattr(-,root,root)
#%doc */*.sample* AUTHORS COPYING
#%doc doc/quagga.html
#%doc doc/mpls
#%doc ChangeLog INSTALL NEWS README REPORTING-BUGS SERVICES TODO
#%dir %attr(750,root,root) %{_sysconfdir}
%dir %attr(750,root,root) /var/log/quagga
#%dir %attr(755,root,root) /usr/share/info
%dir %attr(750,root,root) /var/run/quagga
#%{_infodir}/*info*
%{_mandir}/man*/*
%{_sbindir}/zebra
%{_sbindir}/ospfd
#%{_sbindir}/ripd
#%{_sbindir}/bgpd
#%{_sbindir}/watchquagga
#%{_sbindir}/ripngd
%{_sbindir}/ospf6d
#%{_sbindir}/isisd
#%dir %attr(-,root,root) %{_libdir}
#%dir %{_libdir}
%{_libdir}/lib*.so
%{_libdir}/lib*.so.*
#%config(noreplace) %{_sysconfdir}/quagga/[!v]*
%config %{_sysconfdir}/rc.d/init.d/*
#%config(noreplace) %{_sysconfdir}/sysconfig/quagga
#%config(noreplace) /etc/pam.d/quagga
#%config(noreplace) %attr(640,root,root) /etc/logrotate.d/*

%changelog
* Thu Feb 16 2012 Pukong.wjm <pukong.wjm@taobao.com> 1.0.0
- first create package
