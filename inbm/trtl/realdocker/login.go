/*
   Copyright (C) 2017-2024 Intel Corporation
   SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/api/types/registry"
)

// Login authenticates a server with the given authentication credentials.
// It will return an authentication body and any error encountered.
func Login(dw DockerWrapper, username string, serverAddress string) (registry.AuthenticateOKBody, error) {

	buf := bufio.NewReader(os.Stdin)
	fmt.Print("Enter password: ")
	result, err := buf.ReadString('\n')
	result = strings.TrimSuffix(result, "\n")

	if err != nil {
		return registry.AuthenticateOKBody{}, err
	}

	authConfig := registry.AuthConfig{
		Username:      username,
		Password:      result,
		ServerAddress: serverAddress,
	}

	authBody, err := dw.Login(authConfig)

	if err != nil {
		return registry.AuthenticateOKBody{}, err
	} else {
		return authBody, err
	}
}
