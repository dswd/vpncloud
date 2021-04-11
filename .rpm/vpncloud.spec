%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: vpncloud
Summary: Peer-to-peer VPN
Version: @@VERSION@@
Release: @@RELEASE@@
License: GPL-3.0
Group: Applications/System
Source0: %{name}-%{version}.tar.gz
URL: https://vpncloud.ddswd.de

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

%description
%{summary}

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
mkdir -p %{buildroot}/etc/vpncloud
chmod 700 %{buildroot}/etc/vpncloud
mkdir -p %{buildroot}/lib/systemd/system
mkdir -p %{buildroot}/usr/share/man/man1
cp %{buildroot}/../../../../../assets/example.net.disabled %{buildroot}/etc/vpncloud/example.net.disabled
cp %{buildroot}/../../../../../assets/vpncloud@.service %{buildroot}/lib/systemd/system/vpncloud@.service
cp %{buildroot}/../../../../../assets/vpncloud.target %{buildroot}/lib/systemd/system/vpncloud.target
cp %{buildroot}/../../../../../assets/vpncloud-wsproxy.service %{buildroot}/lib/systemd/system/vpncloud-wsproxy.service
cp %{buildroot}/../../../../../target/vpncloud.1.gz %{buildroot}/usr/share/man/man1/vpncloud.1.gz
cp -a * %{buildroot}

%clean
rm -rf %{buildroot}

%files
/etc/vpncloud
/etc/vpncloud/example.net.disabled
/usr/bin/vpncloud
/lib/systemd/system/vpncloud@.service
/lib/systemd/system/vpncloud.target
/lib/systemd/system/vpncloud-wsproxy.service
/usr/share/man/man1/vpncloud.1.gz

%defattr(-,root,root,-)
%{_bindir}/*
