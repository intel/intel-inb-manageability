# AOTA Updates

## Supported AOTA commands and their functionality:

### Supported ***docker*** commands

| *docker* Command | Definition                                                                                                                                                                                                                                       |
|:-----------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Import           | Importing an image to the device and starting a container                                                                                                                                                                                        |
| List             | Lists all containers for all images that are either 'latest' or have a tag number.  It will list the container ID, state, and image name.  It will provide 'NONE' for the container ID and state if the image does not have an active container. | 
| Load             | Loading an image from the device and starting a container                                                                                                                                                                                        |
| Pull             | Pulls an image or a repository from a registry and starting a container                                                                                                                                                                          |
| Remove           | Removes docker images from the system                                                                                                                                                                                                            |
| Stats            | Returns a live data stream for all the running containers                                                                                                                                                                                        |

### Supported ***docker-compose*** commands

| *docker-compose* Command | Definition                                                                    |
|:-------------------------|:------------------------------------------------------------------------------|
| Up                       | Deploying a service stack on the device                                       |
| Down                     | Stopping a service stack on the device                                        |
| Pull                     | Pulls an image or a repository from a registry and starting the service stack |
| List                     | Lists containers                                                              |
| Remove                   | Removes docker images from the system                                         |

### Supported ***Application*** commands

| *application* Command | Definition                      |
|:----------------------|:--------------------------------|
| Update                | Updating an application package |

## Fields in the AOTA form:

| Field                                             | Description                                                                                                                                                                                                                                                  |
|:--------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| App                                               | Docker or Docker-compose or Application                                                                                                                                                                                                                      |
| Command                                           | **Docker-Compose:** Up, Down, Pull, List and Remove.  <p>**Docker operation**s: Load, Import, Pull, Remove and Stats</p>                                                                                                                                     |
| Container Tag                                     | Name tag for image/container.                                                                                                                                                                                                                                |
| Docker Compose File                               | Specify custom yaml file for docker-compose command. Example: *custom.yml*                                                                                                                                                                                   |
| Fetch                                             | Server URL to download the AOTA container *tar.gz* <p>❗ If the server requires username/password to download the file then provide this information in server username server password                                                                       |
| Server username/<p>Server Password</p>            | If server needs credentials; specify the username and password                                                                                                                                                                                               |
| Version                                           | Each container will have a version number tag. You are recommended to use this version number under version in the AOTA trigger. ```docker images```. See image below for result.                                                                            |
| Docker Registry Docker Registry Username/Password | Specify Docker Registry if accessing any registry other than the default <em>index.docker.io.  <p>Optional fields Docker Registry Username/Password can be used to access docker private images in AOTA through docker and docker-compose up, pull commands. |
