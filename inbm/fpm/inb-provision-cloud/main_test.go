/*
@copyright: Copyright 2017-2023 Intel Corporation All Rights Reserved.
@license: Intel, see licenses/LICENSE for more details.
*/

package main

import "testing"

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
		"deviceToken", "serverIp", "serverPort", "/path/to/cert", "", "", "")
	expected := `{ "cloud": "thingsboard", "config": caPath deviceToken serverIp serverPort /path/to/cert }`
	if actual != expected {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}

func TestMakeUCCJson(t *testing.T) {
	actual := makeCloudJson("ucc", "{CA_PATH} {TOKEN} {HOSTNAME} {PORT} {CLIENT_CERT_PATH}", "caPath",
		"deviceToken", "serverIp", "serverPort", "/path/to/cert", "/path/to/key", "proxy.co.com", "911")
	expected := `{ "cloud": "ucc", "config": caPath deviceToken serverIp serverPort /path/to/cert }`
	if actual != expected {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}
