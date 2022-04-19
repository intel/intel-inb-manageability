# Manageability Docker
This folder contains the build instructions for creating mangeability docker container packages for Azure and Thingsboard cloud service providers.

PLEASE NOTE: You must have 'btrfs-progs' and 'snapper' installed on the host machine for Ubuntu or Debian based OSes, for btrfs-based snapshot/rollback functionality to work with system updates.

## BUILD INSTRUCTIONS

* Prepare a Linux machine with git and Docker installed.  Ensure the 'm4' and 'bash' packages are also installed (these are available in all major Linux distributions).
* If you are behind a proxy, ensure your http_proxy, https_proxy, and no_proxy variables are set correctly and exported.  E.g., in bash, you could run: "http_proxy=http://foo.com:1234/ && export http_proxy"
* Optional but recommended for better build speed and caching: export DOCKER_BUILDKIT=1
* Run: ./build-azure-container.sh for Azure (or) ./build-thingsboard-container.sh for Thingsboard. 
* When build is complete, build output will be in the output folder. For Azure, use package named inb_azure_container.zip, for Thingsboard use inb_thingsboard_container.zip

## HOW TO BUILD INB IMAGE AND START THE CONTAINER

* Unzip the package(inb_azure_container.zip/inb_thingsboard_container.zip).
* If using the provided `sample_customer_mqtt_client` please refer [HOW TO USE THE SAMPLE CUSTOMER MQTT CLIENT](#how-to-use-the-sample-customer-mqtt-client). 
* If using Thingsboard, edit the thingsboard_conf_file and fill in the respective Thingsboard server details and device tokens along with tls certificate of thingsboard server if TLS is enabled on the Thingsboard server. If using TLS for Thingsboard uncomment the line 'cp /src/thingsboard.pub.pem /etc/intel-manageability/secret/cloudadapter-agent/thingsboard.pub.pem' in the cloud_source file.
* If using Azure, edit the azure_conf_file and fill in the Primary SAS Key, device name, scope id.
* Now run ./run.sh which builds the docker image and starts the container.


If an error such as 'unable to resolve' or a DNS error or 'unable to look up' is seen near the start of the build, follow the instructions under https://docs.docker.com/install/linux/linux-postinstall/ --> "DISABLE DNSMASQ".  This can occur in some Linux distributions that put 127.0.0.1 in /etc/resolv.conf.


## HOW TO USE THE SAMPLE CUSTOMER MQTT CLIENT
* Unzip the package built (inb_azure_container.zip/inb_thingsboard_container.zip)
* Open the cloud_source file and uncomment the lines specified in the file. 
* Create a directory for storing certs on host device and edit the mqtt_client.py file variables DEFAULT_MQTT_CERTS, CLIENT_CERTS, CLIENT_KEYS to point to your local directory with the same cert,key names as seen in the file Ex: /home/harsha/certs/cmd-program.crt to be modified to <your_directory>/cmd-program.crt.
* Edit the run.sh file’s docker run command by adding the additional mount point
```
-v <your_directory>:/var/certs
```
* Edit the thingsboard_conf_file file with your configuration
* Run the following command
```shell
 sudo ./run.sh
```
* Wait until all the services are up and running on the INBM container.
* Run the mqtt_client.py 
```shell
sudo python3 mqtt_client.py
```
* Trigger the manifest(refer email below) from the TB server and you should be able to see the move command received on the console that is running the mqtt_client.py.