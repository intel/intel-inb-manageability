/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"iotg-inb/trtl/dockercompose"
	"iotg-inb/trtl/util"
)

// Used for unit testing
var composeDown = dockercompose.Down
var composeDownWithFile = dockercompose.DownWithFile
var composeUp = dockercompose.Up
var composeUpWithFile = dockercompose.UpWithFile
var composeList = dockercompose.List
var composeLogs = dockercompose.Logs
var composeImagesRemoveAll = dockercompose.ImageRemoveAll
var composePull = dockercompose.Pull
var composePullWithFile = dockercompose.PullWithFile

// ComposeInfo is a struct that contains ComposeInfo-specific instance information
type ComposeInfo struct{}

var execCommand = exec.Command

var dockerComposeDir = "/var/cache/manageability/dispatcher-docker-compose"

// Down stops containers and removes containers, networks, volumes, and images created by Up
func (compose *ComposeInfo) Down(instanceName string) {
	if err := composeDown(util.ExecCommandWrap{}, instanceName); err != nil {
		osExit(1)
	}
}

// Down stops containers and removes containers, networks, volumes, and images created by Up using
//the designated YML file
func (compose *ComposeInfo) DownWithFile(instanceName string, fileName string) {
	if err := composeDownWithFile(util.ExecCommandWrap{}, instanceName, fileName); err != nil {
		osExit(1)
	}
}

// Lists all the running containers of a specific image name
func (compose *ComposeInfo) List(instanceName string) {
	if err := composeList(util.ExecCommandWrap{}, instanceName); err != nil {
		osExit(1)
	}
}

// Check if docker username or docker registry strings are safe with good characters
func is_username_registry_safe(username string, serverName string) bool {
        re := regexp.MustCompile("^[a-zA-Z0-9_.\\-:]*$")
        if (!re.MatchString(username)) || (!re.MatchString(serverName)) {
                return false
        }
        return true

}

// Login authenticates a docker private registry with the given authentication credentials
func (compose *ComposeInfo) Login(username string, serverName string) {
	// Ideally we shouldn't need this method to be implemented, but instead call the Docker Login Directly from
	// Dispatcher-agent, but because all commands are tied to the app type it will call the Compose Login instead
	// of the Docker one.

	if !is_username_registry_safe(username, serverName) {
            fmt.Fprintf(os.Stderr, "Error: No special characters allowed in username/registry. List of good characters include: [a-z], [A-Z], [0-9], . , - , _, :")
                osExit(1)
        }

	buf := bufio.NewReader(os.Stdin)
	fmt.Print("> ")
	inputString, err := buf.ReadString('\n')
	dockerLoginPswd := strings.TrimSuffix(inputString, "\n")

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error %s reading input", err)
		osExit(1)
	}

	dockerPath := ""
	_, err = os.Stat("/usr/bin/docker")
	if os.IsNotExist(err) {
		_, err = os.Stat("/usr/local/bin/docker")
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Cannot find docker")
		} else {
			dockerPath = "/usr/local/bin/docker"
		}
	} else {
		dockerPath = "/usr/bin/docker"
	}

	cmd := exec.Command(dockerPath, "login", "-u", username, "--password-stdin", serverName)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't get stdin for docker login: %s", err.Error())
		osExit(1)
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, dockerLoginPswd)
	}()

	if err := cmd.Start(); nil != err {
		fmt.Fprintf(os.Stderr, "Error starting docker login program: %s, %s", cmd.Path, err.Error())
		osExit(1)
	}

	if err := cmd.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "Error while running docker login program: %s", err.Error())
		osExit(1)
	}

	fmt.Print("Login success")
}

// ImageRemoveAll removes all images of a specific name
func (compose *ComposeInfo) ImageRemoveAll(instanceName string, force bool) {
	if err := composeImagesRemoveAll(util.ExecCommandWrap{}, instanceName); err != nil {
		osExit(1)
	}
}

// Logs retrieves the log output from docker-compose
// instanceName is required to move to the correct directory prior to calling command.
// options are the command line options that can be used with docker-compose logs
// target is an optional service.  If not provided all services will be sent.
func (compose *ComposeInfo) Logs(instanceName string, options string, target string) {
	if err := composeLogs(util.ExecCommandWrap{}, options, instanceName, target); err != nil {
		osExit(1)
	}
}

// Pull pulls the latest changes of all images mentioned in the file
func (compose *ComposeInfo) Pull(instanceName string) {
	if err := composePull(util.ExecCommandWrap{}, instanceName); err != nil {
		osExit(1)
	}
}

// PullWithFile pulls the latest changes of all images mentioned in the file.  Uses the designated YML file.
func (compose *ComposeInfo) PullWithFile(instanceName string, fileName string) {
	if err := composePullWithFile(util.ExecCommandWrap{}, instanceName, fileName); err != nil {
		osExit(1)
	}
}

// Up builds, (re)creates, starts, and attaches to containers for a service.
func (compose *ComposeInfo) Up(instanceName string) {
	if err := composeUp(util.ExecCommandWrap{}, instanceName); err != nil {
		osExit(1)
	}
}

// Up builds, (re)creates, starts, and attaches to containers for a service.  Uses the designated YML file.
func (compose *ComposeInfo) UpWithFile(instanceName string, fileName string) {
	if err := composeUpWithFile(util.ExecCommandWrap{}, instanceName, fileName); err != nil {
		osExit(1)
	}
}
