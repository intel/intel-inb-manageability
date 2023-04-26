install_dependencies:
	sudo gem install winrm winrm-elevated
	vagrant plugin install vagrant-proxyconf

setup:
	rm -rf inb-files
	( cd .. && ./build-windows.sh )
	cp -r ../output-windows/windows inb-files
	cp ../integration-reloaded/test/ucc/UCC_FLOW_TEST.py inb-files

destroy:
	vagrant destroy -f || true

test:
	VAGRANT_DISABLE_VBOXSYMLINKCREATE=1 NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 vagrant up --provider virtualbox


provision:
	VAGRANT_DISABLE_VBOXSYMLINKCREATE=1 NO_PROXY=127.0.0.1 no_proxy=127.0.0.1 vagrant provision

