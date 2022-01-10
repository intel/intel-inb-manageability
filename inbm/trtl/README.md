
# 🐢 TRTL

Provides uniform interface for install/rollback for back ends such as Docker, Docker-Compose, and Snapper.

## Setup
Copy the '/packaging/config/trtl.conf' file -> '/etc'

## Acquiring go

If you need go, follow these instructions: [https://golang.org/doc/install](https://golang.org/doc/install)

## Acquiring TRTL

There are two ways to acquire trtl:

* First method (recommended):
  * Set up ssh access to https://github.com/intel/intel-inb-manageability (see [Connecting to GitHub with SSH](https://docs.github.com/en/authentication/connecting-to-github-with-ssh))
  * Instruct your git to treat https urls to https://github.com/intel/intel-inb-manageability as SSH urls: 
	  * run `git config --global url.ssh://git@github.com/intel/intel-inb-manageability instead of https://github.com/intel/intel-inb-manageability
  * Acquire trtl: `go get -v intel-inb-manageability/inbm/trtl`

* Second method: Go convention is to clone source into path matching repository.  
  * Clone into `$GOPATH/src/intel-inb-manageability/inbm`

## 🛠️ Run, Build, and Test TRTL

All instructions below assume you are in `$GOPATH/src/intel-inb-manageability/inbm/trtl`.

### Build

 ❗ First ensure your dependencies are up to date.  
- run `scripts/set-up-trtl-deps`

* To build statically linked go libraries (dynamically linked to e.g. pthread, libc): `go build -o trtl`
* To build fully statically linked (takes longer): `CGO_ENABLE=0 go build -o trtl`

### Run
 `trtl`

### Test

 `go test ./...`

# Commands

# OS Snapshot Commands

## ⚙️ DeleteSnapshot
### Description
Deletes the specified snapshot.

❗ If -config is not provided => 'rootConfig' is used as the default.

### Usage
```
trtl -type=btrfs -cmd=deleteSnapshot -iv=SNAPSHOT_NUMBER [-config=CONFIG_FILE_NAME]
```
### Example
```
trtl -type=btrfs -cmd=deleteSnapshot -iv=1
```

## ⚙️ SingleSnapshot
### Description
Uses Snapper to create a single snapshot using BTRFS.  Used with type=btrfs only.

❗ If -config is not provided => 'rootConfig' is used as the default.

### Usage
```
trtl -type=btrfs -cmd=singlesnapshot [-config=CONFIG_FILE_NAME] [-description=desc]
```
### Example
```
trtl -type=btrfs -cmd=singlesnapshot -description=desc
```


## ⚙️ UndoChange
### Description
Undoes the changes after the snapshot versions.

❗ If -config is not provided => 'rootConfig' is used as the default.

### Usage
```
 trtl -type=btrfs -cmd=undoChange -sv=SNAPSHOT_VERSION [-config=CONFIG_FILE_NAME]
```
### Example
```
trtl -type=btrfs -cmd=undoChange -sv=1
```

# Docker Container Commands
All commands are for Docker, unless otherwise stated that they are Docker-compose only or support both Docker and Docker-compose

## ⚙️ Commit
### Description
Commits a container by ID to a given commit tag; with provided comment.

### Usage
```
trtl [-type=docker] -cmd=commit -in=IMAGE_NAME -iv=IMAGE_VERSION
```
### Example
```
trtl -cmd=commit -in=sample-container -iv=3
```

## ⚙️ ContainerCopy
### Description
Copies a TAR file to a container and decompresses it at the given path.  

### Usage
```
trtl [-type=docker] 
   -cmd=containercopy 
   -src=IMAGE_SOURCE 
   [-path=PATH; default='/' ]
   -file=FILE_TO_TRANSFER
```

### Example
```
trtl -cmd=containercopy -src=sample-container:2 -path=/ -file=/home/user/artifacts/output/rpm.tar
```


## ⚙️ Exec
### Description
Executes a given command in a given instance and version.  If options string has an execCommand then the cmd executed will be overwritten with this string.  Either execCommand or the options parameter are required.

### Usage
❗ if using the -opt parameter, then the ec value will be overwritten if provided.  Either -ec or -opt are required.
```
trtl -cmd=exec -in=IMAGE_NAME -iv=IMAGE_VERSION {-ec="<command>" | -opt=OPTIONS}
```
Docker Container Options
   - Bind - []string
   - Device - []string
   - ExecCmd - string
   - Label - []string
   - Port - []string - Ex. \"Port\":[\"80/tcp:80\"]


### Example
```
trtl -cmd=exec -in=sample-container -iv=2 -ec="<command>"
```
```
trtl -cmd=exec -in=rpm-hdclite -iv=3 
   -opt=\"[{\"Device\": [\"/dev/sdb1\"], \"ExecCmd\":[\"/bin/bash -c ls /dev/sdb1\",\"/bin/bash\"]}]"
```


## ⚙️ List
### Description
Lists all containers for all images that are either 'latest' or have a tag number.  It will list the container ID, state, and image name.  It will provide 'NONE' for the container ID and state if the image does not have an active container.

### Usage
```
trtl [-type=docker] -cmd=list -in=IMAGE_NAME
```

### Example
```
trtl -cmd=list
```

## ⚙️ ContainerRemove
### Description
Removes the container image of the specified containerID.  It can optionally force the removal of a running container.

### Usage
```
trtl [-type=docker] -cmd=containerRemove 
   -in=IMAGE_NAME 
   -iv=IMAGE_VERSION 
   [-f=FORCE (true | false); default=false]
```

### Example
```
trtl -cmd=containerRemove -in=sample-container -iv=3 -f=true
```


## ⚙️ ContainerRemoveById
### Description
Removes a specific container image by ID.

### Usage
```
trtl [-type=docker] -cmd=containerRemoveById 
   -id=CONTAINER_ID 
   [-f=FORCE (true | false); default=false]
```

### Example
#### Remove all container images with id=ABCD that are not running
```shell
trtl -cmd=containerRemoveById -id=ABCD
```
#### Remove all container images with id=ABCD (running or not)
```shell
trtl -cmd=containerRemoveById -id=ABCD -f=true
```

## ⚙️ ContainerRemoveAll
### Description
Removes all container images. 

### Usage
```shell
trtl [-type=docker] -cmd=containerRemoveAl} 
   [-f=FORCE (true | false); default=false] 
   [-in=IMAGE_NAME]
```
### Example
#### Remove all containers images that are not running
```
trtl -cmd=containerRemoveAll 
```
#### Remove all container images; including containers that are running
```
trtl -cmd=containerRemoveAll -f=true
```
#### Remove all container images that are based off the specified image name and are not running
```
trtl -cmd=containerRemoveAll -in=sample-container
```
#### Remove all container images that are based off the specified image name; including conatiners that are running
```
trtl -cmd=containerRemoveAll -in=sample-container -f=true
```


## ⚙️ DockerBenchSecurity
### Description
Creates a new container which runs Docker Bench Security script against all existing images and containers.

### Usage
```
trtl -cmd=dockerBenchSecurity
```
### Example
```
trtl -cmd=dockerBenchSecurity
```

## ⚙️ Down
### Description
Stops a running container matching the specified image name and version

❗ Docker Compose only.

### Usage
```
trtl -type=compose -cmd=down -in=IMAGE_NAME [-cf=COMPOSE_FILE]
```
### Example
```
trtl -type=compose -cmd=down -in=sample-container
```

## ⚙️ GetImageByContainerId
### Description
Retrieves the image ID and image name for the specified container ID

### Usage
```
trtl [-type=docker] -cmd=getimagebycontainerid -id=CONTAINER_ID
```
### Example
```
trtl -cmd=getimagebycontainerid -id=7f3
```

## ⚙️ GetLastestTag
### Description
Gets the latest version number of the specified image

### Usage
```
trtl [-type=docker] -cmd=getlatesttag -in=IMAGE_NAME
```
### Example
```
trtl -cmd=getlatesttag -in=sample-container
```


## ⚙️ ImageDeleteOld
### Description
Removes all images except the latest 'n' images configured in the TRTL configuration file for the given image name.  This will include removing both containers and images.

### Usage
```
trtl [-type=docker] -cmd=imagedeleteold -in=IMAGE_NAME
```

### Example
```
trtl -cmd=imagedeleteOld -in=sample-container
```

## ⚙️ ImagePull
### Description
Pulls an image from a remote repository.  

### Usage
 ```
 trtl [-type=docker] -cmd=imagepull -ref=REFERENCE [-user=USERNAME]
 ```
 - referenceName = name of the reference from which to pull the image
 - username = name of the user for private repositories
 
### Example
 #### Pull image from a public repository
```
trtl -cmd=imagepull -ref=hello-world
```
#### Pull image from a private repository requiring a username/password
```
 trtl -cmd=imagepull -ref=https://test.intel.com -user=abc
```

## ⚙️ ImageRemove
### Description
Removes a specific image.

### Usage
```
trtl [-type=docker] -cmd=imageRemove 
   -in=IMAGE_NAME 
   -iv=IMAGE_VERSION 
   [-f=FORCE (true | false); default=false]
```

### Example
```
trtl -cmd=imageRemove -in=sample-container -iv=3
```

## ⚙️ ImageRemoveAll
### Description
Removes all images on the system if imageName is not specified.  If an image name is specified, then all images matching that name will be removed.  If an image has a container active, then it will not be removed unless force=true.

❗ Supports both Docker and Docker-compose.

❗ Images can not have a dependency on them or an error will occur.
 
### Usage
```
trtl [-type=docker | compose; default=docker] -cmd=imageRemoveAll
   [-in=IMAGE_NAME]
   [-f=FORCE (true | false); default=false]
```
### Example 
#### Remove all images that do not have active containers
```
trtl -cmd=imageRemoveAll
```
#### Remove all images (active containers or not)
```
trtl -cmd=imageRemoveAll -f=true
```
#### Remove all images that match the image name and do not have active containers
```
trtl -cmd=imageRemoveAll -in=sample-container
```
#### Remove all images that match the name even (active containers or not)
```
trtl -cmd=imageRemoveAll -in=sample-container -f=true
```

## ⚙️ ImageRemoveById
### Description
Removes a specific image by ID.  If an image has a container active, then it will not be removed unless force=true.

### Usage
```
trtl [-type=docker] -cmd=imageRemoveById 
   -id=IMAGE_ID 
   [-f=FORCE (true | false); default=false]
```

### Example
```
trtl -cmd=imageRemoveById -id=ABCD
```

## ⚙️ Import
### Description
Imports the contents from a compressed TAR to create a filesystem image.

### Usage
```
trtl [-type=docker] -cmd=import 
   -src=SOURCE_URL 
   [-ref=REFERENCE_NAME]
```
- src = URL of the source image
- ref  = imagename:tag to associate to the new image

### Example
```
trtl -cmd=import 
   -src=https://external_repo/sample-container.tgz 
   -ref=sample-container:10
```

## ⚙️ Load
### Description
Loads an image from a TAR file.  Used with type=docker only.

### Usage
```
trtl [-type=docker] -cmd=load -src=TAR FILE -ref=REFERENCE_NAME
```
### Example
```
trtl -cmd=load -src=sample-container-load.tgz -ref=sample-container
```

## ⚙️ Login
### Description
Authenticates a server with the given authentication credentials

❗ Supports both Docker and Docker-compose.

### Usage
```
trtl [-type=docker | compose; default=docker] -cmd=login 
   -user=USERNAME 
   -svr=SERVER_ADDRESS
```
### Example
```
trtl -cmd=login -user=abc -svr=https://test.intel.com
```

## ⚙️ Logs
### Description
Retrieves logs from target.  Currently can be used by docker or compose.
-t option for timestamp is on by default

❗ Supports both Docker and Docker-compose.

### Usage
```
trtl [-type=docker | compose; default=docker] -cmd=logs 
   -in=IMAGE_NAME 
   [-opt=OPTIONS] 
   [-target=TARGET].
```
-t option for timestamp is on by default

❗ If using -type=compose the docker-compose up must be ran from the /var/cache/manageability/dispatcher-docker-compose directory

### Example
#### Docker Compose - Number of lines to show from the end of the logs
```
trtl -type=compose -cmd=logs -in=simple-compose -opt="--tail=4" -target=web
```

#### Docker - Number of lines to show from the end of the logs
```
trtl -type=docker -cmd=logs -in=busybox -opt="[{\"tail\":\"4\"}]"
```
#### Docker - In the last 1 minute
```
trtl -type=docker -cmd=logs -in=busybox -opt="[{\"since\":\"1m\"}]"
```
#### Docker - Show extra details provided to logs
```
trtl -type=docker -cmd=logs -in=busybox -opt="[{\"details\":\"true\"}]"
```

## ⚙️ Pull
### Description
Pulls the latest changes of all images mentioned in the file

❗ Docker Compose only.

### Usage
```
trtl -type=pull -cmd=up -in=IMAGE_NAME [-cf=COMPOSE_FILE]
```
 - referenceName = name of the reference from which to pull the image
 - username = name of the user for private repositories
 
### Example
```
trtl -type=compose -cmd=up -in=sample-container
```

## ⚙️ Rollback
### Description
Stops and removes any containers associated with the source and destination labels.  It also removes the source image.

### Usage
```
trtl [-type=docker] -cmd=rollback 
   -in=IMAGE_NAME 
   -iv=IMAGE_VERSION 
   -sn=SNAPSHOT_NAME 
   -sv=SNAPSHOT_VERSION
``` 
### Example
```
trtl -cmd=rollback -in=sample-container -iv=3 -sn=sample-container -sv=2
```

## ⚙️ Snapshot
### Description
* Must either provide a IMAGE_VERSION or AUTOMODE=true.
* AUTOMODE=True (default)

### Usage
```
trtl [-type=docker] -cmd=snapshot
   -in=IMAGE_NAME 
   [-iv=IMAGE_VERSION; default=-1] 
   [-am=AUTOMODE (true | false); default=true]
```
### Example
#### Creates a snapshot of a specific version
```
trtl -cmd=snapshot -in=sample-container -iv=3
```
#### Creates snapshot of the latest version
```
trtl -cmd=snapshot -in=sample-container -am=true (will grab the latest version)
```

## ⚙️ Start
### Description
Starts a container.

### Usage
```
trtl [-type=docker] -cmd=start 
   -in=IMAGE_NAME 
   -iv=IMAGE_VERSION 
   [-opt=OPTIONS]
```

### Example
#### Without options
```
trtl -cmd=start -in=sample-container -iv=2
```
#### With options (See Docker documentation for options)
```
trtl -cmd=start -in=sample-container -iv=2 -opt="[{\"Device\": [\"/dev/sdb1\"],
 \"ExecCmd\":[\"/bin/bash -c ls /dev/sdb1\",\"/bin/bash\"]}]"
 trtl -type=compose -cmd=start -in=simple-compose -iv=0
```

## ⚙️ Stats
### Description
Gets the stats of container(s).

### Usage
```
trtl [-type=docker] -cmd=stats 
   [-all=(true | false); default=true] 
   [-in=IMAGE_NAME] 
   [-iv=IMAGE_VERSION]
```

### Example
#### Stats for all containers
```
trtl -cmd=stats
```
#### Stats for a specific container only
```
trtl -cmd=stats -all=false -in=sample-container -iv=3 (will grab stats for only one container.  -all=false MUST BE SET)
```

## ⚙️ Stop
### Description
Stops the container with the given image name and image version.

### Usage
```
trtl [-type=docker | compose; default=docker] -cmd=stop 
   -in=IMAGE_NAME  
   -iv=IMAGE_VERSION
```
### Example
#### Docker
```
trtl -cmd=stop -in=sample-container -iv=2
```
#### Docker-compose
```
trtl -type=compose -cmd=stop -in=simple-compose -iv=0
```

## ⚙️ StopAll
### Description
Stops all containers.  Can also just stop all containers by a specified image name.

### Usage
trtl [-type=docker] -cmd=stopall [-in=IMAGE_NAME]

### Example
#### Stop all containers
```
trtl -cmd=stopall
```

#### Stop all containers based off the image name
```
trtl -cmd=stopall -in=sample-container
```

## ⚙️ StopByID
### Description
Stops a container by containerID.

### Usage
trtl [-type=docker] -cmd=stopbyid -id=CONTAINERID

### Example
trtl -cmd=stopbyid -id=abcdef123


## ⚙️ Up
### Description
Builds, (re)creates, starts, and attaches to containers for a service.

❗ Docker Compose only.

### Usage
```
trtl -type=compose -cmd=up -in=IMAGE_NAME [-cf=COMPOSE_FILE]
```
### Example
```
trtl -type=compose -cmd=up -in=sample-container
```
