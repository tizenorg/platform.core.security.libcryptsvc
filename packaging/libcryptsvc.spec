Name:      libcryptsvc
Summary:    Crypto Service Library
Version:    0.0.1
Release:    6
Group:      Security/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: 	libcryptsvc.manifest
BuildRequires: cmake
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(capi-system-info)

%description
Crypto Service Library.

%package devel
Summary:    Crypto Service Library (Development)
Group:      Security/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
Crypto Service Library (Development).

%prep
%setup -q
cp %{SOURCE1001} .

%build
MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%ifarch %ix86 x86_64
%cmake . -DARCH=x86 -DFULLVER=%{version} -DMAJORVER=${MAJORVER} -DDESCRIPTION="%{summary}"
%else
%cmake . -DARCH=arm -DFULLVER=%{version} -DMAJORVER=${MAJORVER} -DDESCRIPTION="%{summary}"
%endif
make %{?jobs:-j%jobs}

%install
%make_install


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%license  LICENSE.APLv2
%{_libdir}/*.so*
%attr(755,root,root) /opt/etc/duid-gadget

%files devel
%manifest %{name}.manifest
%{_includedir}/*
%{_libdir}/pkgconfig/cryptsvc.pc
