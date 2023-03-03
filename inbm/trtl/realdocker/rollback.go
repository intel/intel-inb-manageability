/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import (
	"errors"
	"fmt"
)

// Rollback stops and removes any containers associated with the source and
// destination labels.  It also removes the source image.
// It returns any error encountered.
func (i Instance) Rollback(f Finder, dw DockerWrapper, old Instance) error {
	// Make sure old image exists before moving forward.
	containerFound, oldContainer, err := f.FindContainer(dw, old.GetImageTag())
	if err != nil || !containerFound {
		return errors.New("unable to find older image to rollback")
	}

	if err = i.removeContainer(f, dw); err != nil {
		return err
	}

	if err = StartContainer(dw, oldContainer.ID); err != nil {
		return err
	}

	return i.removeImage(dw)
}

func (i Instance) removeImage(dw DockerWrapper) error {
	// TODO:  Do we want to force this removal?
	err := RemoveImage(dw, i.GetImageTag(), true)
	if err == nil {
		fmt.Println("Removed image", i.GetImageTag())
	}
	return err
}

func (i Instance) removeContainer(f Finder, dw DockerWrapper) error {
	containerFound, container, err := f.FindContainer(dw, i.GetImageTag())
	if err != nil {
		return err
	}
	if containerFound {
		err = Stop(f, dw, i.GetImageTag())
		if err != nil {
			return err
		}

		err = RemoveContainer(dw, container.ID, false)
		if err == nil {
			fmt.Println("Removed container", container.ID, "associated with "+i.GetImageTag())
		} else {
			return err
		}
	}
	// if already removed, nop

	return err
}
