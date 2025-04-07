# Macros needed by SELinux
%global selinuxtype targeted

Summary:        An agent to manage systems via in-band connection
Name:           inbm
Version:        5.0
Release:        1%{?dist}
Distribution:   Edge Microvisor Toolkit
Vendor:         Intel Corporation
License:        Apache-2.0
URL:            https://github.com/intel/intel-inb-manageability
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz
Source1:        intel_manageability.conf
Source2:        inbm-configuration-replace-FQDN.sh
Source3:        inbm.te
Source4:        inbm.fc
BuildRequires:  golang
BuildRequires:  systemd-rpm-macros
BuildRequires:  selinux-policy-devel
Requires:       (%{name}-selinux if selinux-policy-targeted)

%description
The Intel In-Band Manageability Framework is software which enables an
administrator to perform critical Device Management operations over-the-air
remotely from the cloud.

%package        selinux
Summary:        SELinux security policy for inbm
Requires(post): inbm = %{version}-%{release}
BuildArch:      noarch
%{?selinux_requires}

%description    selinux
SELinux security policy for inbm.

%prep
%setup -q -n %{name}-%{version}

%build
# Build SELinux policy
mkdir selinux
cp -p %{SOURCE3} selinux/
cp -p %{SOURCE4} selinux/
make -f %{_datadir}/selinux/devel/Makefile %{name}.pp

# Build inbd 
cd %{_builddir}/%{name}-%{version}
GOSUMDB=off GO_MOD_MODE=vendor CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -trimpath -mod=$(GO_MOD_MODE) -gcflags="all=-spectre=all -l" -asmflags="all=-spectre=all" -ldflags "-s -w -extldflags '-static' -X main.Version=$version" -o build/inbd

# Build inbc 
GOSUMDB=off GO_MOD_MODE=vendor CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -trimpath -mod=$(GO_MOD_MODE) -gcflags="all=-spectre=all -l" -asmflags="all=-spectre=all" -ldflags "-s -w -extldflags '-static' -X main.Version=$version" -o build/inbc


%install
# Set up bindir
install -d %{buildroot}%{_bindir}

# Install inbd
install -m 755 %{_builddir}/%{name}-%{version}/build/inbd %{buildroot}%{_bindir}/inbd

# Install inbc
install -m 755 %{_builddir}/%{name}-%{version}/build/inbc %{buildroot}%{_bindir}/inbc

# Install service
install -m 755 %{_builddir}/%{name}-%{version}/configs/systemd/inbd.service %{buildroot}%{_unitdir}/inbd.service

# Modify inbd service file to add it into bm-agents group
sed -i '/^Group=inbd$/a SupplementaryGroups=bm-agents' %{buildroot}%{_unitdir}/inbd.service

# Install provision-tc script
install -D -m 0755 %{_builddir}/%{name}-%{version}/scripts/provision-tc %{buildroot}%{_bindir}/provision-tc

# Configure INBM for Edge Microvisor Toolkit specific needs

# Copy intel_manageability.conf over the existing one
install -D -m 0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/intel_manageability.conf
# Copy inbm-configuration-replace-FQDN.sh 
FQDN_REPLACE_SCRIPT_PATH_TARGET=%{_bindir}/inbm-configuration-replace-FQDN.sh
FQDN_REPLACE_SCRIPT_PATH_BUILD=%{buildroot}$FQDN_REPLACE_SCRIPT_PATH_TARGET
install -D -m 0755 %{SOURCE2} "$FQDN_REPLACE_SCRIPT_PATH_BUILD"
# Modify inbd service file to add ExecStartPre to customize config file at runtime for FQDN
sed -i "/^ExecStart/i ExecStartPre=$FQDN_REPLACE_SCRIPT_PATH_TARGET" %{buildroot}%{_unitdir}/inbd.service
# and also inject LP agent variables
sed -i '/^ExecStart/i EnvironmentFile=/etc/edge-node/node/agent_variables' %{buildroot}%{_unitdir}/inbd.service


# make new files/directories so they can be persisted

mkdir %{buildroot}%{_var}/intel-manageability
mkdir %{buildroot}%{_var}/log
touch %{buildroot}%{_var}/log/inbm-update-status.log
echo '"UpdateLog": []' > %{buildroot}%{_var}/log/inbm-update-log.log
touch %{buildroot}%{_sysconfdir}/intel_manageability.conf_bak

# Install SELinux policy
mkdir -p %{buildroot}%{_datadir}/selinux/packages
install -m 644 %{name}.pp %{buildroot}%{_datadir}/selinux/packages/%{name}.pp

%files    selinux
%{_datadir}/selinux/packages/%{name}.pp

%post     selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{name}.pp
# Apply the file contexts
/sbin/restorecon -Rv /usr/bin/inbd
/sbin/restorecon -Rv /etc/intel_manageability.conf

%postun   selinux
%selinux_modules_uninstall -s %{selinuxtype} %{name}


%files

%config(noreplace) %{_sysconfdir}/*
%{_bindir}/*
%{_unitdir}/*
%license LICENSE
%{_var}/cache/manageability/*
%{_var}/intel-manageability
%{_var}/log/*

%pre
    # Create docker group if it doesn't exist
    getent group inbd >/dev/null || groupadd -r inbd


%post
%preun
%postun

%changelog
* Thu Apr 03 2025 Yeng Liong Wong <yeng.liong.wong@intel.com> - 4.2.8.6-1
- Update INBM to v4.2.8.6

* Tue Mar 25 2025 Christopher Nolan <christopher.nolan@intel.com> - 4.2.8.5-3
- Update configuration and agent binary paths to use edge-node/

* Fri Mar 21 2025 Anuj Mittal <anuj.mittal@intel.com> - 4.2.8.5-2
- Bump Release to rebuild

* Mon Mar 17 2025 Gavin Lewis <gavin.b.lewis@intel.com> - 4.2.8.5-1
- Update INBM to v4.2.8.5

* Fri Mar 14 2025 Yeng Liong Wong <yeng.liong.wong@intel.com> - 4.2.8.4-4
- Update files for rebranding.

* Mon Mar 3 2025 Jia Yong Tan <jia.yong.tan@intel.com> - 4.2.8.4-3
- Update SELinux policy.

* Mon Feb 24 2025 Yeng Liong Wong <yeng.liong.wong@intel.com> - 4.2.8.4-2
- Fix SELinux policy to access os-update-tool lock.

* Fri Feb 14 2025 Gavin Lewis <gavin.b.lewis@intel.com> - 4.2.8.4-1
- Rename Emt references

* Tue Jan 21 2025 Yeng Liong Wong <yeng.liong.wong@intel.com> - 4.2.8.2-7
- Add SELinux policy for access os-update-tool lock.

* Fri Jan 17 2025 Jia Yong Tan <jia.yong.tan@intel.com> - 4.2.8.2-6
- Add SELinux policy for root access.

* Tue Jan 07 2025 Naveen Saini <naveen.kumar.saini@intel.com> - 4.2.8.2-5
- Fix license installation.

* Mon Jan 06 2025 Naveen Saini <naveen.kumar.saini@intel.com> - 4.2.8.2-4
- Update Source URL.

* Mon Dec 30 2024 Jia Yong Tan <jia.yong.tan@intel.com> - 4.2.8.2-3
- Add SELinux policy to allow root to read inbm_conf_rw_t

* Fri Dec 20 2024 Jia Yong Tan <jia.yong.tan@intel.com> - 4.2.8.2-2
- Fix SELinux policy

* Wed Dec 18 2024 Yeng Liong Wong <yeng.liong.wong@intel.com> - 4.2.8.2-1
- Update inbm to v4.2.8.2

* Tue Dec 17 2024 Yeng Liong Wong <yeng.liong.wong@intel.com> - 4.2.8-4
- Add missing SELinux policy for INBM

* Wed Dec 4 2024 Yeng Liong Wong <yeng.liong.wong@intel.com> - 4.2.8-3
- Add SELinux policy for INBM

* Wed Dec 4 2024 Gavin Lewis <gavin.b.lewis@intel.com> - 4.2.8-2
- Remove tpm2-abrmd dependency from both INBM and INBM's mqtt service

* Mon Dec 2 2024 Gavin Lewis <gavin.b.lewis@intel.com> - 4.2.8-1
- Update INBM to v4.2.8

* Mon Nov 25 2024 Andy <andy.peng@intel.com> - 4.2.7-2
- Update go build flag to reduce binary size
- -N to enable compiler optimization 

* Tue Nov 19 2024 Gavin Lewis <gavin.b.lewis@intel.com> - 4.2.7-1
- Update INBM version
- Customize INBM config file for Edge Microvisor Toolkit

* Mon Nov 18 2024 Gavin Lewis <gavin.b.lewis@intel.com> - 4.2.6.2-2
- Update INBM config and logging config files

* Fri Oct 25 2024 Yeng Liong Wong <yeng.liong.wong@intel.com> - 4.2.6.2-1
- Update inbm to v4.2.6.2

* Fri Oct 18 2024 Gavin Lewis <gavin.b.lewis@intel.com> - 4.2.6.1-2
- Add psutil as dependency

* Fri Oct 18 2024 Yeng Liong Wong <yeng.liong.wong@intel.com> - 4.2.6.1-1
- Update inbm to v4.2.6.1
- Add inbm-dispatcher to bm-agents group

* Thu Oct 17 2024 Yeng Liong Wong <yeng.liong.wong@intel.com> - 4.2.6-2
- Fix iteration warning during groupadd

* Tue Oct 1 2024 Gavin Lewis <gavin.b.lewis@inteloc.m> - 4.2.6-1
- Pull in latest INBM
- Update dependency list
- Create some files meant to be runtime-persistent at install time

* Wed Sep 4 2024 Gavin Lewis <gavin.b.lewis@intel.com> - 4.2.5-1
- Original version for Edge Microvisor Toolkit. License verified.