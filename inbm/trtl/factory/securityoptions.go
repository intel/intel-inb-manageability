/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"errors"
	"regexp"
)

// SecurityOptions is a structure used to hold AppArmor security options
type SecurityOptions struct {
	AppArmor string
	SecComp  string
}

// SecurityOptionsParse takes a string apparmor=X seccomp=Y or the reverse
// and creates a SecurityOptions struct
func SecurityOptionsParse(securityOptions string) (SecurityOptions, error) {
	emptyOptions := SecurityOptions{AppArmor: "", SecComp: ""}

	r1, err := regexp.Compile("^apparmor=(.*) seccomp=(.*)$")
	if err != nil {
		return emptyOptions, err
	}

	r2, err := regexp.Compile("^seccomp=(.*) apparmor=(.*)$")
	if err != nil {
		return emptyOptions, err
	}

	if r1.MatchString(securityOptions) {
		x := r1.FindAllStringSubmatch(securityOptions, 1)
		return SecurityOptions{AppArmor: x[0][1], SecComp: x[0][2]}, nil
	} else if r2.MatchString(securityOptions) {
		x := r2.FindAllStringSubmatch(securityOptions, 1)
		return SecurityOptions{AppArmor: x[0][2], SecComp: x[0][1]}, nil
	} else if securityOptions == "" {
		return SecurityOptions{AppArmor: "", SecComp: ""}, nil // default
	}
	return SecurityOptions{AppArmor: "", SecComp: ""}, errors.New("invalid format")
}

// AsStringArray returns the security options as an array of strings suitable for the Docker library
func (s SecurityOptions) AsStringArray() []string {
	if s.AppArmor == "" && s.SecComp == "" {
		return []string{}
	}
	return []string{"apparmor=" + s.AppArmor, "seccomp=" + s.SecComp}
}
