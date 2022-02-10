# Manageability Docker
This folder contains the build instructions for creating mangeability docker container packages for Azure and Thingsboard cloud service providers.


## BUILD INSTRUCTIONS

* Prepare a Linux machine with git and Docker installed.  Ensure the 'm4' and 'bash' packages are also installed (these are available in all major Linux distributions).
* If you are behind a proxy, ensure your http_proxy, https_proxy, and no_proxy variables are set correctly and exported.  E.g., in bash, you could run: "http_proxy=http://foo.com:1234/ && export http_proxy"
* Optional but recommended for better build speed and caching: export DOCKER_BUILDKIT=1
* Run: ./build-az-container.sh for Azure (or) ./build-tb-container.sh for Thingsboard. 
* When build is complete, build output will be in the output folder. For Azure, use package named inb_azure_container.zip, for Thingsboard use inb_tb_container.zip

## HOW TO BUILD INB IMAGE AND START THE CONTAINER

* Unzip the package(inb_azure_container.zip/inb_tb_container.zip).
* If planning to use the sample_customer_mqtt_client provided, open the cloud_source file and uncomment the lines specified in the file.
* If using Thingsboard, edit the tb_conf_file and fill in the respective Thingsboard server details and device tokens along with tls certificate of thingsboard server if TLS is enabled on the Thingsboard server. If not using TLS for Thingsboard, remove the line 'RUN cp ./thingsboard.pub.pem /src/thingsboard.pub.pem' in the Dockerfile
* If using Azure, edit the azure_conf_file and fill in the Primary SAS Key, device name, scope id.
* Now run ./run.sh which builds the docker image and starts the container.


If an error such as 'unable to resolve' or a DNS error or 'unable to look up' is seen near the start of the build, follow the instructions under https://docs.docker.com/install/linux/linux-postinstall/ --> "DISABLE DNSMASQ".  This can occur in some Linux distributions that put 127.0.0.1 in /etc/resolv.conf.

