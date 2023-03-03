/*
   Copyright (C) 2017-2023 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"iotg-inb/trtl/factory"
	"iotg-inb/trtl/parser"
	"iotg-inb/trtl/util"
)

const defaultNumImagesKept = "1"
const defaultMaxSeconds = "180"
const defaultOverwriteImageFlag = false

var osExit = os.Exit
var parseValue = parser.ParseConfigValue
var parseBoxType = parser.ValidateBoxType
var parseCmdType = parser.ValidateCommandType
var parseSecurityOptions = factory.SecurityOptionsParse

// usage prints usage and exits with provided exit code
func usage(exitCode int) {
	fmt.Println("Usage: trtl -type=TYPE -cmd=COMMAND (See required and optional arguments under command name below)")
	fmt.Println("")
	fmt.Println("A front end for managing containers or partition sets (instances)")
	fmt.Println("")
	fmt.Println("Options:")
	fmt.Println("      -h  Print usage")
	fmt.Println("")
	fmt.Println("Types: (defaults to docker)")
	fmt.Println("    docker                  issues command via docker")
	fmt.Println("    btrfs                   issues command via btrfs")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("    commit                  create a new image from a container's changes")
	fmt.Println("    copyContainer           copies and decompresses a TAR file to a container. " +
		"{-src=CONTAINER} {-file=NAME} [-PATH=/])")
	fmt.Println("    deleteSnapshot       deletes snapshots starting at 0 to the given snapshot number {-iv=VERSION}")
	fmt.Println("    exec                 run a command in an instance {-in=NAME} {-iv=VERSION} {-ec=COMMAND}")
	fmt.Println("    events               run events command to listen to events continuously")
	fmt.Println("    getlatesttag         gets latest tag for image {-in=NAME}")
	fmt.Println("    list                 list all")
	fmt.Println("    load                 load an image from a tar file {-src=URL} {-ref=name reference}")
	fmt.Println("    containerRemove      kills and removes a container. {-in=NAME and -iv=VERSION}" +
		" [-f=(true | false)]")
	fmt.Println("    containerRemoveById     kills and removes a container by Id. {-id=CONTAINER ID} " +
		"[-f=(true | false)]")
	fmt.Println("    containerRemoveAll      kills and removes all containers. [in=NAME] [f=FORCE (true |false)]")
	fmt.Println("    deleteSnapshot          deletes snapshots starting at 0 to the given snapshot number {-iv=VERSION}")
	fmt.Println("    down                    runs the docker-compose Down command {-in=NAME}")
	fmt.Println("    events                  run events command to listen to events continuously")
	fmt.Println("    exec                    run a command in an instance {-in=NAME} {-iv=VERSION} {-ec=COMMAND}")
	fmt.Println("    getImageByContainerId   retrieves the image id and name associated with the given container id.")
	fmt.Println("    getlatesttag            gets latest tag for image {-in=NAME}")
	fmt.Println("    imageDeleteOld          deletes all but the configured number of images for a given image name.")
	fmt.Println("    imagePull			     pulls an image from a remote registry. {ref=reference name} [-user=USERNAME]")
	fmt.Println("    imageRemove             removes one image. {-in=NAME} {-iv=VERSION}")
	fmt.Println("    imageRemoveAll          removes all images or all images matching name. [in=NAME]" +
		" [f=FORCE (true | false)]")
	fmt.Println("    imageRemoveById         removes an image by Id. {-id=IMAGE ID} [-f=(true | false)]")
	fmt.Println("    import                  import the contents from a tarball to create a filesystem image.  " +
		"{-src=URL} {-ref=name reference}")
	fmt.Println("    login                   authenticates a server with the given authentication credentials. " +
		"{-user=USERNAME} {-svr=SERVER_ADDRESS}")
	fmt.Println("    list                    list all")
	fmt.Println("    load                    load an image from a tar file {-src=URL} {-ref=name reference}")
	fmt.Println("    logs                    retrieve logs from container or service. {-in=NAME} [opt=OPTIONS] [target=TARGET]")
	fmt.Println("    singleSnapshot          takes a single snapshot using snapper.  Only used with BTRFS. " +
		"[-config=CONFIG NAME] [-description=desc]")
	fmt.Println("    rollback                stop an instance and start from earlier snapshot. {-in=NAME}" +
		" {-iv=VERSION} {-sn=SNAPSHOT_NAME} {-sv=SNAPSHOT_VERSION}")
	fmt.Println("    snapshot                take a snapshot of an instance {-in=NAME} [-iv=VERSION] " +
		"[am=AUTOMODE (true|false)]")
	fmt.Println("    stats                   fetches container resource usage statistics")
	fmt.Println("    start                   start an instance {-in=NAME} {-iv=VERSION}")
	fmt.Println("    stop                    stop an instance {-in=NAME} {-iv=VERSION}")
	fmt.Println("    stopAll                 stop all running containers")
	fmt.Println("    stopByID                stop a container {-id=CONTAINER_ID}")
	fmt.Println("    undoChange              undo the changes after the snapshot version " +
		"{-sv=SNAPSHOT_VERSION} [config=CONFIG NAME]")
	fmt.Println("    up                       runs the docker-compose Up command {-in=NAME} [-cf=FILENAME]")
	fmt.Println("    pull                     runs the docker-compose Pull command {-in=NAME} [-cf=FILENAME]")
	osExit(exitCode)
}

func main() {
	if err := os.Setenv("DOCKER_API_VERSION", "1.37"); err != nil {
		fmt.Printf("Unable to set Docker API version.")
		osExit(1)
	}

	typePtr := flag.String("type", "docker", "Box application type")
	autoModePtr := flag.Bool("am", true, "Automatically uses the last version.")
	commandTypePtr := flag.String("cmd", "", "Container command to execute")
	configNamePtr := flag.String("config", "rootConfig", "Configuration file used by Snapper")
	SnapshotDescription := flag.String("description", "defaultdescription", "Description for snapper snapshots")
	forcePtr := flag.Bool("f", false, "Force action")
	fileNamePtr := flag.String("file", "", "Filename to transfer")
	instanceNamePtr := flag.String("in", "", "Instance Name")
	instanceVersionPtr := flag.Int("iv", -1, "Instance Version")
	dockerComposeFilePtr := flag.String("cf", "", "Docker Compose File")
	idPtr := flag.String("id", "", "Container/Image ID")
	executeCommandPtr := flag.String("ec", "", "Execute Command")
	pathPtr := flag.String("path", "/", "Path to use")
	refStringPtr := flag.String("ref", "", "Reference String")
	snapshotNamePtr := flag.String("sn", "", "Snapshot Name")
	snapshotVersionPtr := flag.Int("sv", -1, "Snapshot Version")
	sourcePtr := flag.String("src", "", "Image Source String")
	optionsPtr := flag.String("opt", "", "Options")
	svrAddressPtr := flag.String("svr", "", "Server Address")
	userNamePtr := flag.String("user", "", "Username")

	securityOptPtr := flag.String("security-opt", "", "Security Options")
	targetPtr := flag.String("target", "", "Target of the command")
	flag.Parse()
	tail := flag.Args()

	securityOptions := getSecurityOptions(*securityOptPtr)

	boxType := validateBoxType(*typePtr)

	commandType := validateCommandType(*commandTypePtr, boxType)

	box := createBox(boxType)

	switch commandType {
	case parser.Commit:
		{
			validateStringInput(*instanceNamePtr)
			validateStringFlag("InstanceName", *instanceNamePtr)
			validateIntFlag("InstanceVersion", *instanceVersionPtr)
			box.(factory.Container).Commit(*instanceNamePtr, *instanceVersionPtr)
		}
	case parser.ContainerCopy:
		{
			validateStringFlag("Source", *sourcePtr)
			validateStringFlag("FileName", *fileNamePtr)
			box.(factory.Container).ContainerCopy(*sourcePtr, *fileNamePtr, *pathPtr)
		}
	case parser.ContainerRemove:
		{
			validateStringFlag("InstanceName", *instanceNamePtr)
			validateIntFlag("InstanceVersion", *instanceVersionPtr)

			box.(factory.Container).ContainerRemove(*instanceNamePtr, *instanceVersionPtr, *forcePtr)
		}
	case parser.ContainerRemoveByID:
		{
			validateStringFlag("Container ID", *idPtr)
			box.(factory.Container).ContainerRemoveByID(*idPtr, *forcePtr)
		}
	case parser.ContainerRemoveAll:
		{
			box.(factory.Container).ContainerRemoveAll(*instanceNamePtr, *forcePtr)
		}
	case parser.DeleteSnapshot:
		{
			validateIntFlag("InstanceVersion", *instanceVersionPtr)
			box.(factory.Snapper).DeleteSnapshot(*configNamePtr, *instanceVersionPtr)
		}
	case parser.DockerBenchSecurity:
		{
			box.(factory.Container).DockerBenchSecurity()
		}
	case parser.Down:
		{
			validateStringFlag("InstanceName", *instanceNamePtr)
			if len(*dockerComposeFilePtr) > 0 {
				box.(factory.Composer).DownWithFile(*instanceNamePtr, *dockerComposeFilePtr)
			} else {
				box.(factory.Composer).Down(*instanceNamePtr)
			}
		}
	case parser.Exec:
		{
			validateStringFlag("InstanceName", *instanceNamePtr)
			validateIntFlag("InstanceVersion", *instanceVersionPtr)
			if len(*optionsPtr) == 0 && len(*executeCommandPtr) == 0 {
				fmt.Println("Error: either options and executeCommand parameter is required.")
				osExit(1)
			}
			tail = append(strings.Fields(*executeCommandPtr), tail...)
			box.(factory.Container).Exec(*instanceNamePtr, *instanceVersionPtr, tail, *optionsPtr,
				securityOptions)
		}
	case parser.GetImageByContainerId:
		{
			validateStringFlag("Container ID", *idPtr)
			box.(factory.Container).GetImageByContainerId(*idPtr)
		}
	case parser.GetLatestTag:
		{
			validateStringFlag("InstanceName", *instanceNamePtr)
			box.(factory.Container).GetLatestTag(*instanceNamePtr)
		}
	case parser.ImageDeleteOld:
		{
			imageDeleteOld(box.(factory.Container), *instanceNamePtr)
		}
	case parser.ImagePull:
		{
			validateStringFlag("Reference", *refStringPtr)
			box.(factory.Container).ImagePull(*refStringPtr, *userNamePtr, getMaxWaitTime())
		}
	case parser.ImageRemove:
		{
			validateStringFlag("InstanceName", *instanceNamePtr)
			validateIntFlag("InstanceVersion", *instanceVersionPtr)
			box.(factory.Container).ImageRemove(*instanceNamePtr, *instanceVersionPtr, *forcePtr)
		}
	case parser.ImageRemoveAll:
		{
			if boxType == factory.Compose {
				box.(factory.Composer).ImageRemoveAll(*instanceNamePtr, *forcePtr)
			} else {
				box.(factory.Container).ImageRemoveAll(*instanceNamePtr, *forcePtr)
			}
		}
	case parser.ImageRemoveById:
		{
			validateStringFlag("Image ID", *idPtr)
			box.(factory.Container).ImageRemoveByID(*idPtr, *forcePtr)
		}
	case parser.Import:
		{
			imageImport(box.(factory.Container), *sourcePtr, *refStringPtr)
		}
	case parser.List:
		{
			box.List(*instanceNamePtr)
		}
	case parser.Load:
		{
			imageLoad(box.(factory.Container), *sourcePtr, *refStringPtr)
		}
	case parser.Login:
		{
			validateStringFlag("Username", *userNamePtr)
			validateStringFlag("ServerAddress", *svrAddressPtr)
			if boxType == factory.Compose {
				box.(factory.Composer).Login(*userNamePtr, *svrAddressPtr)
			} else {
				box.(factory.Container).Login(*userNamePtr, *svrAddressPtr)
			}
		}
	case parser.Logs:
		{
			validateStringFlag("InstanceName", *instanceNamePtr)
			if boxType == factory.Compose {
				box.(factory.Composer).Logs(*instanceNamePtr, *optionsPtr, *targetPtr)
			} else {
				box.(factory.Container).Logs(*instanceNamePtr, *optionsPtr, *targetPtr)
			}
		}
	case parser.SingleSnapshot:
		{
			box.(factory.Snapper).SingleSnapshot(*configNamePtr, *SnapshotDescription)
		}
	case parser.Pull:
		{
			validateStringFlag("Reference", *refStringPtr)
			if len(*dockerComposeFilePtr) > 0 {
				box.(factory.Composer).PullWithFile(*refStringPtr, *dockerComposeFilePtr)
			} else {
				box.(factory.Composer).Pull(*refStringPtr)
			}
		}
	case parser.Rollback:
		{
			validateStringFlag("InstanceName", *instanceNamePtr)
			validateIntFlag("InstanceVersion", *instanceVersionPtr)
			validateStringFlag("SnapshotName", *snapshotNamePtr)
			validateIntFlag("SnapshotVersion", *snapshotVersionPtr)
			box.(factory.Container).Rollback(*instanceNamePtr, *instanceVersionPtr, *snapshotNamePtr, *snapshotVersionPtr)
		}
	case parser.Snapshot:
		{
			snapshot(box.(factory.Container), *instanceNamePtr, *instanceVersionPtr, *autoModePtr)
		}
	case parser.Start:
		{
			validateStringFlag("InstanceName", *instanceNamePtr)
			validateIntFlag("InstanceVersion", *instanceVersionPtr)
			box.(factory.Container).Start(*instanceNamePtr, *instanceVersionPtr, *optionsPtr,
				securityOptions)
		}
	case parser.Stats:
		{
			box.(factory.Container).Stats()
		}
	case parser.Stop:
		{
			validateStringFlag("InstanceName", *instanceNamePtr)
			validateIntFlag("InstanceVersion", *instanceVersionPtr)
			containerStop(box.(factory.Container), *instanceNamePtr, *instanceVersionPtr)
		}
	case parser.StopAll:
		{
			containerStopAll(box.(factory.Container), *instanceNamePtr)
		}
	case parser.StopByID:
		{
			validateStringFlag("containerID", *idPtr)
			box.(factory.Container).ContainerStopByID(*idPtr)
		}
	case parser.UndoChange:
		{
			validateIntFlag("SnapshotVersion", *snapshotVersionPtr)
			box.(factory.Snapper).UndoChange(*configNamePtr, *snapshotVersionPtr)
		}
	case parser.Events:
		{
			box.(factory.Container).Events()
		}
	case parser.Up:
		{
			validateStringFlag("InstanceName", *instanceNamePtr)

			if len(*dockerComposeFilePtr) > 0 {
				box.(factory.Composer).UpWithFile(*instanceNamePtr, *dockerComposeFilePtr)
			} else {
				box.(factory.Composer).Up(*instanceNamePtr)
			}
		}

	default:
		fmt.Printf("Command '%s' not supported.", commandType)
		osExit(1)
	}

	osExit(0)
}

func getSecurityOptions(options string) []string {
	securityOptionsStruct, err := parseSecurityOptions(options)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to parse security options '%s': %s", options, err)
		osExit(1)
	}
	return securityOptionsStruct.AsStringArray()
}

func createBox(box string) factory.Boxer {
	bb, err := factory.CreateBox(box)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		osExit(1)
	}
	return bb
}

func validateBoxType(box string) string {
	box, err := parseBoxType(box)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		osExit(1)
	}
	return box
}

func validateCommandType(commandType string, boxType string) string {
	commandType, err := parseCmdType(strings.ToLower(commandType), strings.ToLower(boxType))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		usage(1)
	}
	return commandType
}

func snapshot(container factory.Container, instanceName string, instanceVersion int, autoMode bool) {
	validateStringFlag("InstanceName", instanceName)
	if !autoMode {
		validateIntFlag("InstanceVersion", instanceVersion)
	}
	container.Snapshot(instanceName, instanceVersion, autoMode)
}

func imageDeleteOld(container factory.Container, instanceName string) {
	validateStringFlag("InstanceName", instanceName)

	keep, err := parseValue(parser.ConfigFilePath, parser.NumberImagesHeld)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read configuration file.  Using default container type")
		keep = defaultNumImagesKept
	}

	numImagesKept := util.ConvertToInt(keep)

	numImagesKept = verifyNumImagesKeptWithinLimits(numImagesKept)

	container.ImageDeleteOld(numImagesKept, instanceName)
}

func verifyNumImagesKeptWithinLimits(nk int) int {
	// ImagesToKeepMax is the maximum number allowed for XML attack security reasons.
	const imagesToKeepMax = 4

	// ImagesToKeepMin is the minimum number allowed for XML attack security reasons.
	const imagesToKeepMin = 1

	if nk > imagesToKeepMax {
		fmt.Fprintf(os.Stderr, "Number of images to keep must be between %d and %d. Value=%d.  Using set maximum.",
			imagesToKeepMin, imagesToKeepMax, nk)
		return imagesToKeepMax
	}

	if nk < imagesToKeepMin {
		fmt.Fprintf(os.Stderr, "Number of images to keep must be between %d and %d. Value=%d.  Using set minimum.",
			imagesToKeepMin, imagesToKeepMax, nk)
		return imagesToKeepMin
	}
	return nk
}

func verifyWaitTimeWithinLimits(nk int) {
	// ImagesToKeepMax is the maximum number allowed for XML attack security reasons.
	const waitTimeSecsMax = 300

	// ImagesToKeepMin is the minimum number allowed for XML attack security reasons.
	const waitTimeSecsMin = 30

	if nk > waitTimeSecsMax || nk < waitTimeSecsMin {
		fmt.Fprintf(os.Stderr, "Wait Time must be between %d and %d. Value=%d",
			waitTimeSecsMax, waitTimeSecsMin, nk)
		osExit(1)
	}
}

func imageLoad(container factory.Container, src string, ref string) {
	validateStringFlag("Source", src)
	validateStringFlag("Reference", ref)
	maxWaitSeconds := getMaxWaitTime()

	container.Load(src, ref, maxWaitSeconds)
}

func imageImport(container factory.Container, src string, ref string) {
	validateStringFlag("Source", src)
	validateStringFlag("Reference", ref)
	var overwriteImageFlag bool
	flag, err := parseValue(parser.ConfigFilePath, parser.OverwriteImageOnImport)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read configuration file. Using default value for overwriting Image: %t.\n",
			defaultOverwriteImageFlag)
		overwriteImageFlag = defaultOverwriteImageFlag
	} else {
		overwriteImageFlag, err = strconv.ParseBool(flag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error converting overwriteImageFlag in configuration file to boolean: %s", err)
			osExit(1)
		}
	}

	maxWaitSeconds := getMaxWaitTime()

	container.ImageImport(ref, src, maxWaitSeconds, overwriteImageFlag)
}

func containerStop(container factory.Container, instanceName string, instanceVersion int) {
	container.Stop(instanceName, instanceVersion)
}

func containerStopAll(container factory.Container, instanceName string) {
	container.StopAll(instanceName)
}

func getMaxWaitTime() int {
	secs, err := parseValue(parser.ConfigFilePath, parser.DockerWaitTimeInSeconds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read configuration file.  Using default max seconds: %s",
			defaultMaxSeconds)
		secs = defaultMaxSeconds
	}

	secsToWait := util.ConvertToInt(secs)
	verifyWaitTimeWithinLimits(secsToWait)
	return secsToWait
}

func validateStringInput(input string) {
	if strings.Contains(input, "\x00") {
		fmt.Fprintf(os.Stderr, "Invalid characters entered.")
		osExit(1)
	}
}

func validateStringFlag(flagName string, argFlag string) {
	if len(argFlag) == 0 {
		fmt.Fprintf(os.Stderr, "Argument '%s' was empty.", flagName)
		usage(1)
	}
}

func validateIntFlag(flagName string, argFlag int) bool {
	if argFlag == -1 {
		fmt.Fprintf(os.Stderr, "Argument '%s' was empty.", flagName)
		usage(1)
	}
	return true
}
