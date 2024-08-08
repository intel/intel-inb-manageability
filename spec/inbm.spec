Summary:        A framework for managing and updating edge node systems
Name:           inbm
Version:        0.0.0
Release:        1%{?dist}
License:        LicenseRef-Intel
Vendor:         Intel Corporation
Distribution:   Tiber
Group:          Applications/Text
URL:            https://github.com/intel/intel-inb-manageability
Source0:        %{name}-%{version}.tar.gz
%global debug_package %{nil}
%global _build_id_links none
BuildRequires:  golang
BuildRequires:  systemd-rpm-macros
BuildRequires: python3.11
BuildRequires: python3.11-venv

%description
INBM provides a framework for managing and updating edge node systems.

%prep
%setup -q

%build
python3.11 -m venv env
source env/bin/activate
pip install pyinstaller

%install
mkdir -p %{buildroot}/src/inbm
cp -r docs %{buildroot}/src/inbm

%files
/src/inbm/docs


%post
#!/bin/sh
set -e


%postun
#!/bin/sh  -e


%changelog
* Thu Aug 8 2024 Gavin Lewis <gavin.b.lewis@inteloc.m> - 0.0.0-1
- Original version for TiberOS. License verified.
