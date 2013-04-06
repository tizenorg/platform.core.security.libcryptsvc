Name:      libcryptsvc
Summary:   nothing
Version:    0.0.1
Release:    6
Group:      Osp/Security
License:    APLv2
Source0:    %{name}-%{version}.tar.gz
BuildRequires: cmake

BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)

%description

%package devel
Summary: nothing
Group: Bada/Security
Requires: %{name} = %{version}-%{release}

%description devel

%prep
%setup -q

%build
MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%ifarch %{ix86}
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DARCH=x86 -DFULLVER=%{version} -DMAJORVER=${MAJORVER} -DDESCRIPTION=%{summary}
%else
cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} -DARCH=arm -DFULLVER=%{version} -DMAJORVER=${MAJORVER} -DDESCRIPTION=%{summary}
%endif
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cat LICENSE.APLv2 > %{buildroot}/usr/share/license/%{name}
cat LICENSE.Flora >> %{buildroot}/usr/share/license/%{name}

%make_install

%files
%{_libdir}/*.so*
%{_datadir}/license/%{name}

%files devel
%{_includedir}/*
%{_libdir}/pkgconfig/cryptsvc.pc
