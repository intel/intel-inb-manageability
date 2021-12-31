install_dependencies:
	sudo apt install vagrant
	sudo apt install virtualbox
	sudo gem install winrm winrm-elevated

setup:
	rm -rf inb-files
	( cd .. && ./build-windows.sh )
	cp -r ../output-windows/windows inb-files

destroy:
	vagrant destroy -f || true

test:
	VAGRANT_DISABLE_VBOXSYMLINKCREATE=1 vagrant up --provider virtualbox
