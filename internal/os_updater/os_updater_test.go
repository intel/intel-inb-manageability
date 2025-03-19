package osupdater

import (
	//"fmt"
	"fmt"
	"testing"

	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
	"github.com/stretchr/testify/assert"
)

func TestUpdateOS_Success(t *testing.T) {
	mockFactory := &MockUpdaterFactory{
		CreateDownloaderFunc: func(pb.UpdateSystemSoftwareRequest_DownloadMode) Downloader {
			return &MockDownloader{
				DownloadFunc: func() error { return nil },
			}
		},
		CreateUpdaterFunc: func() Updater {
			return &MockUpdater{
				UpdateFunc: func() error { return nil },
			}
		},
		CreateRebooterFunc: func() Rebooter {
			return &MockRebooter{
				RebootFunc: func() error { return nil },
			}
		},
	}

    req := &pb.UpdateSystemSoftwareRequest{Mode: pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_FULL}
    resp, err := UpdateOS(req, mockFactory)

    assert.NoError(t, err)
    assert.Equal(t, int32(200), resp.StatusCode)
    assert.Empty(t, resp.Error)
}

func TestUpdateOS_DownloadError(t *testing.T) {
    mockFactory := &MockUpdaterFactory{
        CreateDownloaderFunc: func(pb.UpdateSystemSoftwareRequest_DownloadMode) Downloader {
            return &MockDownloader{
                DownloadFunc: func() error { return fmt.Errorf("download error") },
            }
        },
    }

    req := &pb.UpdateSystemSoftwareRequest{Mode: pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_FULL}
    resp, err := UpdateOS(req, mockFactory)

    assert.NoError(t, err)
    assert.Equal(t, int32(500), resp.StatusCode)
    assert.Equal(t, "download error", resp.Error)
}

func TestUpdateOS_UpdateError(t *testing.T) {
    mockFactory := &MockUpdaterFactory{
        CreateDownloaderFunc: func(pb.UpdateSystemSoftwareRequest_DownloadMode) Downloader {
            return &MockDownloader{
                DownloadFunc: func() error { return nil },
            }
        },
        CreateUpdaterFunc: func() Updater {
            return &MockUpdater{
                UpdateFunc: func() error { return fmt.Errorf("update error") },
            }
        },
    }

    req := &pb.UpdateSystemSoftwareRequest{Mode: pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_FULL}
    resp, err := UpdateOS(req, mockFactory)

    assert.NoError(t, err)
    assert.Equal(t, int32(500), resp.StatusCode)
    assert.Equal(t, "update error", resp.Error)
}

func TestUpdateOS_RebootError(t *testing.T) {
    mockFactory := &MockUpdaterFactory{
        CreateDownloaderFunc: func(pb.UpdateSystemSoftwareRequest_DownloadMode) Downloader {
            return &MockDownloader{
                DownloadFunc: func() error { return nil },
            }
        },
        CreateUpdaterFunc: func() Updater {
            return &MockUpdater{
                UpdateFunc: func() error { return nil },
            }
        },
        CreateRebooterFunc: func() Rebooter {
            return &MockRebooter{
                RebootFunc: func() error { return fmt.Errorf("reboot error") },
            }
        },
    }

    req := &pb.UpdateSystemSoftwareRequest{Mode: pb.UpdateSystemSoftwareRequest_DOWNLOAD_MODE_FULL}
    resp, err := UpdateOS(req, mockFactory)

    assert.NoError(t, err)
    assert.Equal(t, int32(500), resp.StatusCode)
    assert.Equal(t, "reboot error", resp.Error)
}

