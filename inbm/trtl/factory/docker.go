/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"fmt"
	"strings"

	"os"
	"iotg-inb/trtl/realdocker"
)

var listContainers = realdocker.ListContainers
var load = realdocker.Load
var copyToContainer = realdocker.CopyToContainer
var removeContainer = realdocker.RemoveContainer
var removeAllContainers = realdocker.RemoveAllContainers
var imageDeleteOld = realdocker.ImageDeleteOld
var imageImport = realdocker.ImageImport
var imagePull = realdocker.ImagePull
var login = realdocker.Login
var removeImage = realdocker.RemoveImage
var removeAllImages = realdocker.RemoveAllImages
var removeLatestContainerFromImage = realdocker.RemoveLatestContainerFromImage
var stats = realdocker.Stats
var stop = realdocker.Stop
var stopAll = realdocker.StopAll
var getImageByContainerId = realdocker.GetImageByContainerId

// DockerInfo is a struct that contains DockerInfo-specific instance information
type DockerInfo struct{}

func (docker *DockerInfo) DockerBenchSecurity() {
	dw := realdocker.DockerWrap{}
	err := realdocker.DockerBenchSecurity(dw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing Docker Bench Security: %s", err)
		osExit(1)
	}
}

// Exec corresponds to the docker exec command.  It executes a given command in a given instance and version.
// If options string has an execCommand then the cmd executed will be overwritten with this string.  Either execCommand
// or the options parameter are required.
func (docker *DockerInfo) Exec(instanceName string, instanceVersion int, execCommand []string, options string,
	securityOptions []string) {
	i := realdocker.NewInstance(instanceVersion, instanceName, realdocker.CreateStartCommand())
	f := realdocker.DockerFinder{}
	dw := realdocker.DockerWrap{}
	err := i.Exec(f, dw, execCommand, getContainerOptionsFromString(options), securityOptions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing command %s with container %s: %s",
			execCommand, i.GetImageTag(), err)
		osExit(1)
	} else {
		fmt.Println("Execution complete")
	}
}

// GetLatestTag will return the latest version number the image specified is using.
func (docker *DockerInfo) GetLatestTag(name string) {
	dw := realdocker.DockerWrap{}
	if strings.Contains(name, "*") {
		fmt.Fprintf(os.Stderr, "Invalid image name '%s'", name)
		osExit(1)
	}
	fmt.Println(getLatestImageTag(dw, name))
}

// GetImageByContainerId will return the image name associated with the specified container ID.
func (docker *DockerInfo) GetImageByContainerId(containerID string) {
	dw := realdocker.DockerWrap{}
	imageID, imageName, err:= realdocker.GetImageByContainerId(dw, containerID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error GetImageByContainerId: %s ", err)
		osExit(1)
	}
	fmt.Println("ImageID=", imageID, ",ImageName=", imageName)
}

// List corresponds to the docker imageList and containerList commands.  It lists all docker
// containers for all images that are either 'latest' or have a tag number.
// It will list the container ID, state, and image name.  It will provide 'NONE' for the container ID
// and state if the image does not have an active container.
func (docker *DockerInfo) List(instanceName string) {
	dw := realdocker.DockerWrap{}
	if err := listContainers(dw, instanceName); err != nil {
		fmt.Fprintf(os.Stderr, "Error listing image/container information: %s", err)
		osExit(1)
	}
}

// Events corresponds to the docker events api which return an event.
func (docker *DockerInfo) Events() {
	dw := realdocker.DockerWrap{}
	err := realdocker.Events(dw)
	if err != nil {
		osExit(1)
	}
}

// Load will load an image from the tar ball specified
func (docker *DockerInfo) Load(path string, ref string, maxWaitSeconds int) {
	dw := realdocker.DockerWrap{}
	f := realdocker.DockerFinder{}
	if err := load(f, dw, path, ref, maxWaitSeconds); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading image: %s", err)
		osExit(1)
	}
}

// Login authenticates a server with the given authentication credentials.
func (docker *DockerInfo) Login(username string, serverName string) {
	dw := realdocker.DockerWrap{}
	result, err := realdocker.Login(dw, username, serverName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error authenticating with server: %s", err)
		osExit(1)
	}
	fmt.Fprintf(os.Stdout, "Status: '%s'", result.Status)
}

// Rollback removes the specified instance name and version and starts the specified snapshot name and version instead.
func (docker *DockerInfo) Rollback(instanceName string, instanceVersion int, snapshotName string, snapshotVersion int) {
	from := realdocker.NewInstance(instanceVersion, instanceName, nil)
	to := realdocker.NewInstance(snapshotVersion, snapshotName, nil)
	f := realdocker.DockerFinder{}
	dw := realdocker.DockerWrap{}
	err := from.Rollback(f, dw, to)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error rolling %s back to %s: %s", from.GetImageTag(), to.GetImageTag(), err)
		osExit(1)
	}
}

func getLatestImageTag(dw realdocker.DockerWrap, name string) int {
	found, latestTag, err := realdocker.GetLatestImageVersionNumber(dw, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting latest image version number for image '%s': %s", name, err)
		osExit(1)
	}

	if !found {
		fmt.Fprintf(os.Stderr, "Error finding image: %s", name)
		osExit(1)
	}

	return latestTag
}

// Snapshot will create a new snapshot of the given image and version.
// If autoMode is set to true, then the latest version will be used in creating the snapshot.
func (docker *DockerInfo) Snapshot(instanceName string, instanceVersion int, autoMode bool) {
	var i realdocker.Instance
	dw := realdocker.DockerWrap{}
	if autoMode {
		i = realdocker.NewInstance(getLatestImageTag(dw, instanceName), instanceName, nil)
	} else {
		i = realdocker.NewInstance(instanceVersion, instanceName, nil)
	}

	f := realdocker.DockerFinder{}
	if _, err := i.Snapshot(f, dw); err != nil {
		fmt.Fprintf(os.Stderr, "Error performing snapshot: %s", err)
		osExit(1)
	}
}

// Commit corresponds to docker commit.
// It will commit the given instance name and version.
func (docker *DockerInfo) Commit(instanceName string, instanceVersion int) {
	i := realdocker.NewInstance(instanceVersion, instanceName, nil)
	df := realdocker.DockerFinder{}
	dw := realdocker.DockerWrap{}
	if err := i.Commit(df, dw); err != nil {
		fmt.Fprintf(os.Stderr, "Error committing containers '%s': %s", i.GetImageTag(), err)
		osExit(1)
	}
}

// ContainerCopy copies and decompresses a tar file from a filesystem to a container.
func (docker *DockerInfo) ContainerCopy(src string, fileName string, path string) {
	df := realdocker.DockerFinder{}
	dw := realdocker.DockerWrap{}
	if err := copyToContainer(df, dw, src, fileName, path); err != nil {
		fmt.Fprintf(os.Stderr, "Error copying to container '%s': %s", src, err)
		osExit(1)
	}
}

// ContainerRemove removes a specified container from the docker host.  If force is true, then
// a running container can also be removed.
func (docker *DockerInfo) ContainerRemove(instanceName string, instanceVersion int, force bool) {
	i := realdocker.NewInstance(instanceVersion, instanceName, nil)
	f := realdocker.DockerFinder{}
	dw := realdocker.DockerWrap{}
	if err := removeLatestContainerFromImage(f, dw, i.GetImageTag(), force); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing container '%s': %s", i.GetImageTag(), err)
		osExit(1)
	}
}

// ContainerRemoveByID removes a specified container by container_id from the docker host.  If force is true, then
// a running container can also be removed.
func (docker *DockerInfo) ContainerRemoveByID(containerID string, force bool) {
	dw := realdocker.DockerWrap{}
	if err := removeContainer(dw, containerID, force); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing container '%s': %s", containerID, err)
		osExit(1)
	}
}

// ContainerRemoveAll will remove all (non-running) containers matching the instanceName.  If force is true, then
// running containers will also be removed.
func (docker *DockerInfo) ContainerRemoveAll(instanceName string, force bool) {
	dw := realdocker.DockerWrap{}
	if err := removeAllContainers(dw, instanceName, force); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing all containers using image '%s': %s", instanceName, err)
		osExit(1)
	}
}

// ImageDeleteOld will keep the most recent number of images specified in the config.xml file and delete
// the rest.  This will include removing both containers and images.
func (docker *DockerInfo) ImageDeleteOld(numImagesKept int, imageName string) {
	f := realdocker.DockerFinder{}
	dw := realdocker.DockerWrap{}
	if err := imageDeleteOld(f, dw, numImagesKept, imageName); err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting old images for image name '%s': %s", imageName, err)
		osExit(1)
	}
}

// ImageImport will import the contents from a tarball to create a filesystem image.
// refString is the imagename:tag to associate to the new image, source is the URL of the source
// image, maxWaitSeconds is the number of seconds to wait for image to import.
// overWriteImageFlag is the flag specifying whether to overwrite currently present image
func (docker *DockerInfo) ImageImport(refString string, source string, maxWaitSeconds int, overwriteImageFlag bool) {
	f := realdocker.DockerFinder{}
	dw := realdocker.DockerWrap{}
	if err := imageImport(f, dw, refString, source, maxWaitSeconds, overwriteImageFlag); err != nil {
		fmt.Fprintf(os.Stderr, "Error importing image: %s", err)
		osExit(1)
	}
}

// ImagePull requests the docker host to pull an image from a remote registry.
// referenceName is the name of the reference from which to pull the image
// username is the name of the user for private repositories
// maxSeconds is a timeout to ensure the command will fail at some given amount of time.
func (docker *DockerInfo) ImagePull(refString string, userName string, maxWaitSeconds int) {
	f := realdocker.DockerFinder{}
	dw := realdocker.DockerWrap{}

	if err := imagePull(f, dw, refString, userName, maxWaitSeconds); err != nil {
		fmt.Fprintf(os.Stderr, "Error pulling image: %s", err)
		osExit(1)
	}
}

// ImageRemove will remove the specified image from the docker host.  The image must not have any active
// containers running unless the force parameter is true for it to be removed.
func (docker *DockerInfo) ImageRemove(instanceName string, instanceVersion int, force bool) {
	i := realdocker.NewInstance(instanceVersion, instanceName, nil)
	dw := realdocker.DockerWrap{}
	if err := removeImage(dw, i.GetImageTag(), force); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing container '%s': %s", i.GetImageTag(), err)
		osExit(1)
	}
}

// ImageRemoveAll will remove all instances matching the instanceName.  The images must not have any
// active containers in order to be removed, unless force is true.
func (docker *DockerInfo) ImageRemoveAll(imageName string, force bool) {
	dw := realdocker.DockerWrap{}
	if err := removeAllImages(dw, imageName, force); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing all instances of the image '%s': %s", imageName, err)
		osExit(1)
	}
}

// ImageRemoveByID removes a specified image by image_id from the docker host.  If force is true, image will be forced
// to be removed.
func (docker *DockerInfo) ImageRemoveByID(imageID string, force bool) {
	dw := realdocker.DockerWrap{}
	if err := realdocker.RemoveImage(dw, imageID, force); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing image'%s': %s", imageID, err)
		osExit(1)
	}
}

// Start starts a container matching the specified image name and version.  Options are used
// as container options when creating the container.
func (docker *DockerInfo) Start(instanceName string, instanceVersion int, options string,
	securityOptions []string) {
	i := realdocker.NewInstance(instanceVersion, instanceName, nil)
	dw := realdocker.DockerWrap{}
	f := realdocker.DockerFinder{}
	if _, err := i.Start(f, dw, getContainerOptionsFromString(options), securityOptions); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting container '%s': %s", i.GetImageTag(), err)
		osExit(1)
	}
}

// Logs gets the log files from the latest container of the specified Image name
// Options corresponds to the Docker API ContainerLogOptions and imageName is the image used for the container.
// Target is ignored for type=docker
func (docker *DockerInfo) Logs(options string, imageName string, target string) {
	dw := realdocker.DockerWrap{}
	f := realdocker.DockerFinder{}
	if err := realdocker.Logs(f, dw, getContainerLogOptionsFromString(options), imageName); err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching logs for latest container using image '%s': %s", imageName, err)
		osExit(1)
	}
}

// Stats fetches container usage statistics of all running containers.
func (docker *DockerInfo) Stats() {
	dw := realdocker.DockerWrap{}
	if err := stats(dw); err != nil {
	    fmt.Fprintf(os.Stderr, "Error fetching container stats: %s", err)
		osExit(1)
	}
}

// Stop stops a running container matching the specified image name and version
func (docker *DockerInfo) Stop(instanceName string, instanceVersion int) {
	i := realdocker.NewInstance(instanceVersion, instanceName, nil)
	f := realdocker.DockerFinder{}
	dw := realdocker.DockerWrap{}
	if err := stop(f, dw, i.GetImageTag()); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping container '%s': %s", i.GetImageTag(), err)
		osExit(1)
	}
	fmt.Fprintf(os.Stdout, "Stopped %s", i.GetImageTag())
}

// StopAll stops all running containers
func (docker *DockerInfo) StopAll(imageName string) {
	dw := realdocker.DockerWrap{}
	if err := stopAll(dw, imageName); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping all containers: %s", err)
		osExit(1)
	}
}

// ContainerStopByID stops a running container matching the specified containerID.
func (docker *DockerInfo) ContainerStopByID(containerID string) {
	dw := realdocker.DockerWrap{}
	if err := realdocker.StopContainer(dw, containerID); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping container '%s': %s", containerID, err)
		osExit(1)
	}
}

func getContainerOptionsFromString(options string) realdocker.ContainerOptions {
	if len(options) == 0 {
		return realdocker.ContainerOptions{}
	}

	co, err := realdocker.ContainerOptionsUnmarshal([]byte(options))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing containerOptions: %s", err)
		osExit(1)
	}
	return co[0]
}

func getContainerLogOptionsFromString(options string) realdocker.ContainerLogOptions {
	if len(options) == 0 {
		return realdocker.ContainerLogOptions{}
	}

	clo, err := realdocker.ContainerLogOptionsUnmarshal([]byte(options))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing containerLogOptions: %s", err)
		osExit(1)
	}
	return clo[0]
}
