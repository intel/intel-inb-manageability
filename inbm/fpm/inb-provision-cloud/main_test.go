/*
@copyright: Copyright 2017-2023 Intel Corporation All Rights Reserved.
@license: Intel, see licenses/LICENSE for more details.
*/

package main

import "testing"

func TestServerIpTrue(t *testing.T) {
	inputs := [4]string{"192.0.2.146", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "172.16.254.1",
		"2001:db8:3333:4444:5555:6666:7777:8888"}
	for i := 1; i < len(inputs); i++ {
		actual := isValidIPaddress(inputs[i])
		expected := true
		if actual != expected {
			t.Errorf("expected %v, got %v", expected, actual)
			break
		}
	}

}

func TestServerIpFalse(t *testing.T) {
	inputs := [3]string{"example.com", "www.example.org", "my-server.example.net"}
	for i := 1; i < len(inputs); i++ {
		actual := isValidIPaddress(inputs[i])
		expected := false
		if actual != expected {
			t.Errorf("expected %v, got %v", expected, actual)
			break
		}
	}

}

func TestHostnameTrue(t *testing.T) {
	inputs := [3]string{"example.com", "www.example.org", "my-server.example.net"}
	for i := 1; i < len(inputs); i++ {
		actual := isValidHostname(inputs[i])
		expected := true
		if actual != expected {
			t.Errorf("Invalid Hostname")
			break
		}
	}

}

func TestHostnameFalse(t *testing.T) {
	inputs := [4]string{"example..com", "www.-example.org", "my_server.example.net"}
	for i := 1; i < len(inputs); i++ {
		actual := isValidHostname(inputs[i])
		expected := false
		if actual != expected {
			t.Errorf("Invalid Hostname")
			break
		}
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
		"deviceToken", "serverIp", "serverPort", "/path/to/cert", "", "", "", "")
	expected := `{ "cloud": "thingsboard", "config": caPath deviceToken serverIp serverPort /path/to/cert }`
	if actual != expected {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}

func TestMakeUCCJson(t *testing.T) {
	actual := makeCloudJson("ucc", "{CA_PATH} {TOKEN} {HOSTNAME} {PORT} {CLIENT_CERT_PATH}", "caPath",
		"deviceToken", "serverIp", "serverPort", "/path/to/cert", "/path/to/key", "proxy.co.com", "911", "123456789abc")
	expected := `{ "cloud": "ucc", "config": caPath deviceToken serverIp serverPort /path/to/cert }`
	if actual != expected {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}
