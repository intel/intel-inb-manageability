/*
@copyright: Copyright 2017-2023 Intel Corporation All Rights Reserved.
@license: Intel, see licenses/LICENSE for more details.
*/

package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTrueValidServerId(t *testing.T) {
	inputs := [2]string{"e18122c6-d99f-11ed-bc72-af4d111a5c5e", "172.16.254.1"}
	for i := 1; i < len(inputs); i++ {
		assert.True(t, isServerIdValid(inputs[i]), "Expected valid Server ID.  ID is invalid: "+inputs[i])
	}
}

func TestFalseInvalidServerId(t *testing.T) {
	inputs := [6]string{"18122c6-d99f-11ed-bc72-af4d111a5c5e", "e18122c6-d99f-11ed-bc72-af4d111a5c5",
		"e18122c#-d99f-11ed-bc72-af4d111a5c5e", "e18122c6-d99f-1ed-bc72-af4d111a5c5e", "example.com", "300.300.300.300"}
	for i := 1; i < len(inputs); i++ {
		assert.False(t, isServerIdValid(inputs[i]), "Expected invalid Server ID.  Server ID is valid: "+inputs[i])
	}
}

func TestTrueValidClientId(t *testing.T) {
	inputs := [3]string{"ABCDEF123456", "abcdef123456", "abcdef-1234-5678"}
	for i := 1; i < len(inputs); i++ {
		assert.True(t, isClientIdValid(inputs[i]), "Expected valid Client ID.  Client ID is invalid: "+inputs[i])
	}
}

func TestFalseInvalidClientId(t *testing.T) {
	inputs := [3]string{"clientId#", "clientid+client", "client\x00id"}
	for i := 1; i < len(inputs); i++ {
		assert.False(t, isClientIdValid(inputs[i]), "Expected invalid Client ID.  Client ID is valid: "+inputs[i])
	}
}

func TestServerIpTrue(t *testing.T) {
	inputs := [4]string{"192.0.2.146", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "172.16.254.1",
		"2001:db8:3333:4444:5555:6666:7777:8888"}
	for i := 1; i < len(inputs); i++ {
		assert.True(t, isValidIpAddress(inputs[i]), "Expected valid IP.  IP Address is invalid: "+inputs[i])
	}
}

func TestServerIpFalse(t *testing.T) {
	inputs := [4]string{"example.com", "www.example.org", "my-server.example.net", "300.300.300.300"}
	for i := 1; i < len(inputs); i++ {
		assert.False(t, isValidIpAddress(inputs[i]), "Expected invalid IP.  IP Address is Valid: "+inputs[i])
	}
}

func TestHostnameTrue(t *testing.T) {
	inputs := [3]string{"example.com", "www.example.org", "my-server.example.net"}
	for i := 1; i < len(inputs); i++ {
		assert.True(t, isValidHostname(inputs[i]), "Expected valid hostname.  Hostname is not valid: "+inputs[i])
	}
}

func TestHostnameFalse(t *testing.T) {
	inputs := [4]string{"example..com", "www.-example.org", "my_server.example.net"}
	for i := 1; i < len(inputs); i++ {
		assert.False(t, isValidHostname(inputs[i]), "Expected invalid hostname.  Hostname is valid: "+inputs[i])
	}
}

func TestMakeCustomJson(t *testing.T) {
	actual := makeCustomJson("cloud", "json")
	expected := `{ "cloud": "custom: cloud", "config": json }`
	if actual != expected {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}

func TestMakeAzureJson(t *testing.T) {
	actual := makeAzureJson("scope", "id", "cert", "key", "")
	expected := `{ "cloud": "azure", "config": { "scope_id": "scope", "device_id": "id", "device_cert": "cert", "device_key": "key", "device_sas_key": "" } }`
	if actual != expected {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}

func TestMakeThingsboardJson(t *testing.T) {
	actual := makeCloudJson("thingsboard", "{CA_PATH} {TOKEN} {HOSTNAME} {PORT} {CLIENT_CERT_PATH}", "caPath",
		"deviceToken", "serverIp", "serverPort", "/path/to/cert", "", "", "", "", "")
	expected := `{ "cloud": "thingsboard", "config": caPath deviceToken serverIp serverPort /path/to/cert }`
	if actual != expected {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}

func TestMakeUCCJson(t *testing.T) {
	actual := makeCloudJson("ucc", "{CA_PATH} {TOKEN} {HOSTNAME} {PORT} {CLIENT_CERT_PATH}", "caPath",
		"deviceToken", "serverIp", "serverPort", "/path/to/cert", "/path/to/key", "proxy.co.com", "911",
		"123456789abc", "server1")
	expected := `{ "cloud": "ucc", "config": caPath deviceToken serverIp serverPort /path/to/cert }`
	if actual != expected {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}
