/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"bufio"
	"encoding/base64"
	"github.com/docker/docker/api/types"

	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ImagePull requests the docker host to pull an image from a remote registry.
// referenceName is the name of the reference from which to pull the image
// username is the name of the user for private repositories
// maxSeconds is a timeout to ensure the command will fail at some given amount of time.
func ImagePull(f Finder, dw DockerWrapper, referenceName string, userName string, maxSeconds int) error {
	authStr := ""
	if len(userName) > 0 {
		buf := bufio.NewReader(os.Stdin)
		fmt.Print("Enter password:")
		pwd, err := buf.ReadString('\n')
		pwd = strings.TrimSuffix(pwd, "\n")
		fmt.Print(pwd)
		if err != nil {
			return err
		}

		authConfig := types.AuthConfig{
			Username: userName,
			Password: pwd,
		}

		encodedJSON, err := json.Marshal(authConfig)
		if err != nil {
			return err
		}
		authStr = base64.URLEncoding.EncodeToString(encodedJSON)
	}

	if err := dw.ImagePull(referenceName, types.ImagePullOptions{RegistryAuth: authStr}); err != nil {
		return err
	}

	waitForImage(f, dw, maxSeconds, referenceName)

	imageTag := referenceName
	if !strings.ContainsAny(referenceName, ":") {
		imageTag = referenceName + ":latest"
	}

	_, err := Start(f, dw, ContainerOptions{}, nil, imageTag)
	return err
}
