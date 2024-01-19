/*
@copyright: Copyright 2017-2024 Intel Corporation All Rights Reserved.
@license: Intel, see licenses/LICENSE for more details.
*/

package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestServerNameTrue(t *testing.T) {
	inputs := [7]string{"192.0.2.146", "localhost", "hello-test", "hello_test", "hello.test", "hello,test", "hello1234-_,."}
	for i := 1; i < len(inputs); i++ {
		assert.True(t, isValidServerId(inputs[i]), "Expected valid Server ID.  Server ID is invalid: "+inputs[i])
	}
}

func TestServerNameFalse(t *testing.T) {
	inputs := [4]string{"hello$test", "hello:test", "hello&test", "hello\x00tset"}
	for i := 1; i < len(inputs); i++ {
		assert.False(t, isValidServerId(inputs[i]), "Expected invalid server ID.  Server ID is Valid: "+inputs[i])
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
