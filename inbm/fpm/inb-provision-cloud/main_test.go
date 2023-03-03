/*
@copyright: Copyright 2017-2023 Intel Corporation All Rights Reserved.
@license: Intel, see licenses/LICENSE for more details.
*/

package main

import "testing"

func TestMakeTelitJson(t *testing.T) {
	actual := makeTelitJson("api.devicewise.com", "8883", "thingkey", "token")
	expected := `{ "cloud": "telit", "config": { "hostname": "api.devicewise.com", "port": 8883, ` +
		`"key": "thingkey", "token": "token" } }`
	if actual != expected {
		t.Errorf("expected %s, got %s", expected, actual)
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
	actual := makeThingsboardJson("{CA_PATH} {TOKEN} {HOSTNAME} {PORT} {CLIENT_CERT_PATH}", "caPath",
		"deviceToken", "serverIp", "serverPort", "/path/to/cert")
	expected := `{ "cloud": "thingsboard", "config": caPath deviceToken serverIp serverPort /path/to/cert }`
	if actual != expected {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}
