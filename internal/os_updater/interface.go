package osupdater

import "fmt"

// IUpdaterFactory is an interface that contains the methods to create the concrete classes for the OS updater.
type IUpdaterFactory interface {
	createRebooter() IRebooter
	createUpdater() IUpdater
	createDownloader() IDownloader
}

// GetOSUpdaterFactory returns the correct concrete classes for the OS updater based on the OS type.
func GetOSUpdaterFactory(os string) (IUpdaterFactory, error) {
	if os == "Tiber" {
		return &TiberUpdater{}, nil
	}

	if os == "Ubuntu" {
		return &UbuntuUpdater{}, nil
	}
	return nil, fmt.Errorf("Unsupported OS")
}

// CreateDownloader creates a downloader concrete class for Tiber OS.	
func (t *TiberUpdater) createDownloader() IDownloader {
	return &TiberDownloader{}
}

// CreateOSUpdater creates an OS updater concrete class for Tiber OS.
func (t *TiberUpdater) createUpdater() IUpdater {
	return &TiberUpdater{}
}

// CreateRebooter creates a rebooter concrete class for Tiber OS.
func (t *TiberUpdater) createRebooter() IRebooter {
	return &TiberRebooter{}
}

// CreateDownloader creates a downloader concrete class for Ubuntu OS.
func (u *UbuntuUpdater) createDownloader() IDownloader {
	return &UbuntuDownloader{}
}

// CreateOSUpdater creates an OS updater concrete class for Ubuntu OS.
func (u *UbuntuUpdater) createUpdater() IUpdater {
	return &UbuntuUpdater{}
}

// CreateRebooter creates a rebooter concrete class for Ubuntu OS.
func (u *UbuntuUpdater) createRebooter() IRebooter {
	return &UbuntuRebooter{}
}
