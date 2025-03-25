/*
 * SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * SPDX-License-Identifier: Apache-2.0
 */

// Package osupdater updates the OS.
package osupdater

import (
	"errors"
	//"fmt"
	"io"
	"net/http"
	"os"
	//"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	pb "github.com/intel/intel-inb-manageability/pkg/api/inbd/v1"
)

func TestEMTDownloader_downloadFile(t *testing.T) {
	t.Run("successful download", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		downloader := &EMTDownloader{
			fs: fs,
			request: &pb.UpdateSystemSoftwareRequest{
				Url: "http://example.com/file.txt",
			},
			readJWTTokenFunc: func(afero.Afero, string) (string, error) {
				return "valid-token", nil
			},
			httpClient: &http.Client{
				Transport: roundTripperFunc(func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode: 200,
						Body:       io.NopCloser(strings.NewReader("file content")),
					}
				}),
			},
			requestCreator: http.NewRequest,
		}

		err := downloader.downloadFile()
		assert.NoError(t, err)

		exists, err := afero.Exists(fs, downloadDir+"/file.txt")
		assert.NoError(t, err)
		assert.True(t, exists)

		content, err := afero.ReadFile(fs, downloadDir+"/file.txt")
		assert.NoError(t, err)
		assert.Equal(t, "file content", string(content))
	})

	// t.Run("error loading config", func(t *testing.T) {
	// 	downloader := &EMTDownloader{
	// 		request: &pb.UpdateSystemSoftwareRequest{
	// 			Url: "http://example.com/file.txt",
	// 		},
	// 	}

	// 	LoadConfig = func(path string) (Config, error) {
	// 		return Config{}, errors.New("config error")
	// 	}

	// 	err := downloader.Download()
	// 	assert.EqualError(t, err, "error loading config: config error")
	// })

	t.Run("error creating request", func(t *testing.T) {
		downloader := &EMTDownloader{
			request: &pb.UpdateSystemSoftwareRequest{
				Url: "http://example.com/file.txt",
			},
			readJWTTokenFunc: func(afero.Afero, string) (string, error) {
				return "valid-token", nil
			},
			httpClient: &http.Client{},
			requestCreator: func(method, url string, body io.Reader) (*http.Request, error) {
				return nil, errors.New("error creating request")
			},
		}

		err := downloader.downloadFile()
		assert.EqualError(t, err, "error creating request")
	})

	t.Run("error reading JWT token", func(t *testing.T) {
		downloader := &EMTDownloader{
			request: &pb.UpdateSystemSoftwareRequest{
				Url: "http://example.com/file.txt",
			},
			readJWTTokenFunc: func(afero.Afero, string) (string, error) {
				return "", errors.New("error")
			},
			httpClient:     &http.Client{},
			requestCreator: http.NewRequest,
		}

		err := downloader.downloadFile()
		assert.EqualError(t, err, "error reading JWT token: error")
	})

	t.Run("error performing request", func(t *testing.T) {
		downloader := &EMTDownloader{
			request: &pb.UpdateSystemSoftwareRequest{
				Url: "http://example.com/file.txt",
			},
			readJWTTokenFunc: func(afero.Afero, string) (string, error) {
				return "valid-token", nil
			},
			httpClient: &http.Client{
				Transport: roundTripperFunc(func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode: 500,
						Header:     http.Header{"Content-Length": []string{"4096001"}},
						Body:       http.NoBody,
					}
				}),
			},
			requestCreator: http.NewRequest,
		}

		err := downloader.downloadFile()
		assert.EqualError(t, err, "Status code: 500. Expected 200/Success.")
	})

	// TODO:  This one runs in IDE, but not in Earthly
	// t.Run("error creating file", func(t *testing.T) {
	// 	fs := afero.NewBasePathFs(afero.NewOsFs(), downloadDir)
	// 	downloader := &EMTDownloader{
	// 		fs: fs,
	// 		request: &pb.UpdateSystemSoftwareRequest{
	// 			Url: "http://example.com/file.txt",
	// 		},
	// 		readJWTTokenFunc: func(afero.Afero, string) (string, error) {
	// 			return "valid-token", nil
	// 		},
	// 		httpClient: &http.Client{
	// 			Transport: roundTripperFunc(func(req *http.Request) *http.Response {
	// 				return &http.Response{
	// 					StatusCode: 200,
	// 					Header:     http.Header{"Content-Length": []string{"4096"}},
	// 					Body:       io.NopCloser(strings.NewReader("file content")),
	// 				}
	// 			}),
	// 		},
	// 		requestCreator: http.NewRequest,
	// 	}

	// 	err := downloader.downloadFile()
	// 	assert.Error(t, err)
	// 	assert.Contains(t, err.Error(), "permission denied")
	// })

	t.Run("error copying response body", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		downloader := &EMTDownloader{
			fs: fs,
			request: &pb.UpdateSystemSoftwareRequest{
				Url: "http://example.com/file.txt",
			},
			readJWTTokenFunc: func(afero.Afero, string) (string, error) {
				return "valid-token", nil
			},
			httpClient: &http.Client{
				Transport: roundTripperFunc(func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode: 200,
						Body:       io.NopCloser(errReader{}),
					}
				}),
			},
			requestCreator: http.NewRequest,
		}

		err := downloader.downloadFile()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error copying response body")
	})
}

func TestEMTDownloader_readJWTToken(t *testing.T) {
	fs := afero.NewMemMapFs()

	t.Run("successful read", func(t *testing.T) {
		err := afero.WriteFile(fs, JWTTokenPath, []byte("valid-token"), 0644)
		if err != nil {
			t.Fatalf("failed to write file: %v", err)
		}
		token, err := readJWTToken(afero.Afero{Fs: fs}, JWTTokenPath)
		assert.NoError(t, err)
		assert.Equal(t, "valid-token", token)
	})

	t.Run("file not found", func(t *testing.T) {
		err := fs.Remove(JWTTokenPath)
		if err != nil {
			t.Logf("Warning: failed to remove file: %v", err)
		}
		token, err := readJWTToken(afero.Afero{Fs: fs}, JWTTokenPath)
		assert.Error(t, err)
		assert.Equal(t, "", token)
		assert.True(t, os.IsNotExist(err))
	})

	// TODO: Fix this test
	// t.Run("error reading file", func(t *testing.T) {
	// 	tempDir := t.TempDir
	// 	jwtTokenPath := filepath.Join(tempDir(), "access_token")
	// 	fsa := afero.NewBasePathFs(afero.NewOsFs(), tempDir())

	// 	err := fsa.MkdirAll("", 0755)
	// 	if err != nil {
	// 		t.Fatalf("failed to create directory: %v", err)
	// 	}

	// 	err = fsa.Remove(jwtTokenPath)
	// 	if err != nil {
	// 		t.Logf("Warning: failed to remove file: %v", err)
	// 	}

	// 	err = afero.WriteFile(fsa, "access_token", []byte("token"), 0644)
	// 	if err != nil {
	// 		t.Fatalf("failed to write file: %v", err)
	// 	}

	// 	err = fsa.Chmod("access_token", 0000)
	// 	if err != nil {
	// 		t.Fatalf("failed to change file permissions: %v", err)
	// 	}

	// 	token, err := readJWTToken(afero.Afero{Fs: fs}, jwtTokenPath)
	// 	if err != nil {
	// 		fmt.Println(err.Error())
	// 	}

	// 	assert.Error(t, err, "expected an error due to permission issues")
	// 	assert.Equal(t, "", token)
	// 	assert.True(t, os.IsPermission(err), "expected a permission error")
	// })
}

func TestEMTDownloader_checkDiskSpace(t *testing.T) {
	tests := []struct {
		name           string
		statfs         func(path string, stat *unix.Statfs_t) error
		readJWTToken   func(fs afero.Afero, path string) (string, error)
		httpClient     *http.Client
		requestCreator func(method string, url string, body io.Reader) (*http.Request, error)
		expectedResult bool
		expectedError  error
	}{
		{
			name: "successful check with enough disk space",
			statfs: func(path string, stat *unix.Statfs_t) error {
				stat.Bavail = 1000
				stat.Bsize = 4096
				return nil
			},
			readJWTToken: func(afero.Afero, string) (string, error) {
				return "valid-token", nil
			},
			httpClient: &http.Client{
				Transport: roundTripperFunc(func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode: 200,
						Header:     http.Header{"Content-Length": []string{"4096000"}},
						Body:       http.NoBody,
					}
				}),
			},
			requestCreator: http.NewRequest,
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name: "error getting disk space",
			statfs: func(path string, stat *unix.Statfs_t) error {
				return errors.New("disk space error")
			},
			readJWTToken: func(afero.Afero, string) (string, error) {
				return "", nil
			},
			httpClient:     &http.Client{},
			requestCreator: http.NewRequest,
			expectedResult: false,
			expectedError:  errors.New("disk space error"),
		},
		{
			name: "error reading JWT token",
			statfs: func(path string, stat *unix.Statfs_t) error {
				stat.Bavail = 1000
				stat.Bsize = 4096
				return nil
			},
			readJWTToken: func(afero.Afero, string) (string, error) {
				return "", errors.New("token error")
			},
			httpClient:     &http.Client{},
			requestCreator: http.NewRequest,
			expectedResult: false,
			expectedError:  errors.New("token error"),
		},
		{
			name: "JWT token is empty",
			statfs: func(path string, stat *unix.Statfs_t) error {
				stat.Bavail = 1000
				stat.Bsize = 4096
				return nil
			},
			readJWTToken: func(afero.Afero, string) (string, error) {
				return "", nil
			},
			httpClient:     &http.Client{},
			requestCreator: http.NewRequest,
			expectedResult: false,
			expectedError:  errors.New("empty JWT token"),
		},
		{
			name: "error creating request",
			statfs: func(path string, stat *unix.Statfs_t) error {
				stat.Bavail = 1000
				stat.Bsize = 4096
				return nil
			},
			readJWTToken: func(afero.Afero, string) (string, error) {
				return "valid-token", nil
			},
			httpClient: &http.Client{},
			requestCreator: func(method, url string, body io.Reader) (*http.Request, error) {
				return nil, errors.New("error")
			},
			expectedResult: false,
			expectedError:  errors.New("error creating request: error"),
		},
		{
		    name: "error performing request",
		    statfs: func(path string, stat *unix.Statfs_t) error {
		        stat.Bavail = 1000
		        stat.Bsize = 4096
		        return nil
		    },
		    readJWTToken: func(afero.Afero, string) (string, error) {
		        return "valid-token", nil
		    },
		    httpClient: &http.Client{
		        Transport: roundTripperFunc(func(req *http.Request) *http.Response {
		            return &http.Response{
		                StatusCode: 500,
		                Header:     http.Header{"Content-Length": []string{"4096001"}},
		                Body:       http.NoBody,
		            }
		        }),
		    },
			requestCreator: http.NewRequest,
		    expectedResult: false,
		    expectedError:  nil,
		},
		{
			name: "error performing GET request",
			statfs: func(path string, stat *unix.Statfs_t) error {
				stat.Bavail = 1000
				stat.Bsize = 4096
				return nil
			},
			readJWTToken: func(afero.Afero, string) (string, error) {
				return "valid-token", nil
			},
			httpClient: &http.Client{
				Transport: roundTripperFunc(func(req *http.Request) *http.Response {
					if req.Method == "HEAD" {
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{},
						}
					}
					return nil // Simulate error in GET request
				}),
			},
			requestCreator: http.NewRequest,
			expectedResult: false,
			expectedError:  errors.New("error performing GET request: Get \"http://example.com\": http: RoundTripper implementation (osupdater.roundTripperFunc) returned a nil *Response with a nil error"),
		},
		{
			name: "error reading response body",
			statfs: func(path string, stat *unix.Statfs_t) error {
				stat.Bavail = 1000
				stat.Bsize = 4096
				return nil
			},
			readJWTToken: func(afero.Afero, string) (string, error) {
				return "valid-token", nil
			},
			httpClient: &http.Client{
				Transport: roundTripperFunc(func(req *http.Request) *http.Response {
					return &http.Response{
						StatusCode: 200,
						Header:     http.Header{},
						Body:       io.NopCloser(errReader{}), // Simulate error reading body
					}
				}),
			},
			requestCreator: http.NewRequest,
			expectedResult: false,
			expectedError:  errors.New("error reading response body: error copying response body"),
		},
		{
			name: "successful GET request with Content-Length",
			statfs: func(path string, stat *unix.Statfs_t) error {
				stat.Bavail = 1000
				stat.Bsize = 4096
				return nil
			},
			readJWTToken: func(afero.Afero, string) (string, error) {
				return "valid-token", nil
			},
			httpClient: &http.Client{
				Transport: roundTripperFunc(func(req *http.Request) *http.Response {
					if req.Method == "HEAD" {
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{},
						}
					}
					return &http.Response{
						StatusCode: 200,
						Header:     http.Header{"Content-Length": []string{"4096000"}},
						Body:       http.NoBody,
					}
				}),
			},
			requestCreator: http.NewRequest,
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name: "status code not OK after GET request",
			statfs: func(path string, stat *unix.Statfs_t) error {
				stat.Bavail = 1000
				stat.Bsize = 4096
				return nil
			},
			readJWTToken: func(afero.Afero, string) (string, error) {
				return "valid-token", nil
			},
			httpClient: &http.Client{
				Transport: roundTripperFunc(func(req *http.Request) *http.Response {
					if req.Method == "HEAD" {
						return &http.Response{
							StatusCode: 200,
							Header:     http.Header{},
						}
					}
					return &http.Response{
						StatusCode: 404,
						Header:     http.Header{"Content-Length": []string{"4096000"}},
						Body:       http.NoBody,
					}
				}),
			},
			requestCreator: http.NewRequest,
			expectedResult: false,
			expectedError:  errors.New("Status code: 404. Expected 200/Success."),
		},		
		{
		    name: "content length header missing",
		    statfs: func(path string, stat *unix.Statfs_t) error {
		        stat.Bavail = 1000
		        stat.Bsize = 4096
		        return nil
		    },
		    readJWTToken: func(afero.Afero, string) (string, error) {
		        return "valid-token", nil
		    },
		    httpClient: &http.Client{
		        Transport: roundTripperFunc(func(req *http.Request) *http.Response {
		            return &http.Response{
		                StatusCode: 200,
		                Header:     http.Header{},
		            }
		        }),
		    },
			requestCreator: http.NewRequest,
		    expectedResult: false,
		    expectedError:  errors.New("content-Length header is missing"),
		},
		{
		    name: "not enough disk space",
		    statfs: func(path string, stat *unix.Statfs_t) error {
		        stat.Bavail = 100
		        stat.Bsize = 4096
		        return nil
		    },
		    readJWTToken: func(afero.Afero, string) (string, error) {
		        return "valid-token", nil
		    },
		    httpClient: &http.Client{
		        Transport: roundTripperFunc(func(req *http.Request) *http.Response {
		            return &http.Response{
		                StatusCode: 200,
		                Header:     http.Header{"Content-Length": []string{"4096000"}},
		            }
		        }),
		    },
			requestCreator: http.NewRequest,
		    expectedResult: false,
		    expectedError:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			downloader := &EMTDownloader{
				statfs:           tt.statfs,
				readJWTTokenFunc: tt.readJWTToken,
				httpClient:       tt.httpClient,
				requestCreator:   tt.requestCreator,
				request:          &pb.UpdateSystemSoftwareRequest{Url: "http://example.com"},
			}
			result, err := downloader.checkDiskSpace()
			assert.Equal(t, tt.expectedResult, result)
			if tt.expectedError != nil {
				assert.EqualError(t, err, tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// roundTripperFunc is a helper type to mock http.RoundTripper
type roundTripperFunc func(req *http.Request) *http.Response

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}
