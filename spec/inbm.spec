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

%description
INBM provides a framework for managing and updating edge node systems.

%prep
%setup -q

%build
# ... build here

%install
# mkdir -p %{buildroot}/opt/lp/bin
# mkdir -p %{buildroot}%{_sysconfdir}/lp/node/confs
# mkdir -p %{buildroot}%{_sysconfdir}/sudoers.d
# mkdir -p %{buildroot}%{_unitdir}
# cp build/artifacts/platform-update-agent %{buildroot}/opt/lp/bin/platform-update-agent
# cp configs/platform-update-agent.yaml %{buildroot}%{_sysconfdir}/lp/node/confs/platform-update-agent.yaml
# cp configs/sudoers.d/platform-update-agent %{buildroot}%{_sysconfdir}/sudoers.d/platform-update-agent
# cp debian/platform-update-agent.service %{buildroot}%{_unitdir}/platform-update-agent.service

%files
# /opt/lp/bin/platform-update-agent
# %config(noreplace) %{_sysconfdir}/lp/node/confs/platform-update-agent.yaml
# %{_sysconfdir}/sudoers.d/platform-update-agent
# %{_unitdir}/platform-update-agent.service

%post
#!/bin/sh
set -e

# Commands to run after installation
# echo "Running post-installation script..."

# echo "Getting updateServiceURL..."
# RET="update-node.kind.internal:443"
# if [ ! -z "$RET" ]; then
    # sed -i "s/^updateServiceURL: '.*'/updateServiceURL: '$RET'/" %{_sysconfdir}/lp/node/confs/platform-update-agent.yaml
# fi
# echo "Getting updateServiceURL complete."

# echo "Getting UUID..."
# sed -i "s/^GUID: '.*'/GUID: '$(cat /sys/class/dmi/id/product_uuid)'/" %{_sysconfdir}/lp/node/confs/platform-update-agent.yaml
# echo "Getting UUID complete."

# echo "Assigning id to bm-agents group..."
# groupadd -f bm-agents --system

# id -u platform-update-agent >/dev/null 2>&1 || useradd platform-update-agent --system -g bm-agents
# echo "Assigning id to bm-agents group complete."

# echo "Assigning permission..."
# mkdir -p %{_var}/lp/pua
# chmod 740 %{_var}/lp/pua
# chown platform-update-agent:bm-agents %{_var}/lp/pua

# mkdir -p %{_sysconfdir}/default/grub.d
# touch %{_sysconfdir}/default/grub.d/90-platform-update-agent.cfg
# chown platform-update-agent:bm-agents %{_sysconfdir}/default/grub.d/90-platform-update-agent.cfg

# echo "Assigning permission complete."
# echo "Post-installation complete."

%postun
#!/bin/sh  -e
# echo "Running post-uninstallation script"
# userdel platform-update-agent
# rm -f %{_sysconfdir}/default/grub.d/90-platform-update-agent.cfg %{_sysconfdir}/lp/node/confs/platform-update-agent.yaml
# rm -rf %{_var}/lp/pua
# echo "Successfully purged platform-update-agent"

%changelog
* Thu Aug 8 2024 Gavin Lewis <gavin.b.lewis@inteloc.m> - 0.0.0-1
- Original version for TiberOS. License verified.
