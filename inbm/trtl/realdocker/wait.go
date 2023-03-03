/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"k8s.io/apimachinery/pkg/util/wait"
	"time"
)

var waitForImage = func(f Finder, dw DockerWrapper, maxSecs int, ref string) error {
	err := wait.Poll(3*time.Second, time.Duration(maxSecs)*time.Second,
		func() (bool, error) {
			imageID, err := f.FindImage(dw, ref)
			if len(imageID) > 0 {
				return true, nil
			}
			if err != nil {
				return false, nil
			}
			return false, err
		})
	return err
}
