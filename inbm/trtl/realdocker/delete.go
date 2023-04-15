/*
    Copyright (C) 2017-2023 Intel Corporation
    SPDX-License-Identifier: Apache-2.0
*/

package realdocker

import "fmt"

// ImageDeleteOld will keep the most recent number of images specified in the config.xml file and delete
// the rest.  This will include removing both containers and images.
// It returns any error encountered.
func ImageDeleteOld(f Finder, dw DockerWrapper, numImagesToKeep int, imageName string) error {
	_, highestVerNumber, err := GetLatestImageVersionNumber(dw, imageName)
	if err != nil {
		return err
	}

	images, err := GetAllImagesByName(dw, imageName)
	if err != nil {
		return err
	}

	numberImages := len(images)

	// Highest image number to remove
	h := highestVerNumber - numImagesToKeep

	// Number of images to remove
	numToRemove := numberImages - numImagesToKeep

	count := 0
	ver := h
	for count < numToRemove {
		i := NewInstance(ver, imageName, nil)
		imageTag := i.GetImageTag()

		imageExists := false
		for _, n := range images {
			for _, rtn := range n.RepoTags {
				if rtn == imageTag {
					fmt.Println("Found image: ", imageTag)
					imageExists = true
					break
				}
			}
		}

		if imageExists {
			// Stop container.
			fmt.Println("Stopping: ", imageTag)
			if err := Stop(f, dw, imageTag); err != nil {
				return err
			}

			// Remove container
			fmt.Println("Removing latest container: ", imageTag)
			if err := RemoveLatestContainerFromImage(f, dw, imageTag, false); err != nil {
				return err
			}

			// Remove image
			fmt.Println("Removing image: ", imageTag)
			if err := RemoveImage(dw, imageTag, true); err != nil {
				return err
			}
		}

		ver--
		count++
	}

	return nil
}
