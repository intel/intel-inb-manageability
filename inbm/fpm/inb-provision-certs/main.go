/*

 */

package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

const bitSize = 3072

func usage() {
	_, _ = fmt.Fprintf(os.Stderr, "usage: inb-provision-certs [public directory] [secret directory]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	daysExpiry := "2555"

	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		log.Fatalln("Please specify public and secret directories for certs.")
	}

	publicDir, err := filepath.Abs(args[0])
	must(err, "Getting absolute public directory")
	secretDir, err := filepath.Abs(args[1])
	must(err, "Getting absolute secret directory")

	// ensure publicDir and secretDir directories already exist
	isDirPublic, _ := isDir(publicDir)
	if !isDirPublic {
		log.Fatalf("Public directory does not exist: %s\n", publicDir)
	}

	isDirSecret, _ := isDir(secretDir)
	if !isDirSecret {
		log.Fatalf("Secret directory does not exist: %s\n", secretDir)
	}

	setUpMqttCaDirectories(secretDir, publicDir, daysExpiry)
	setUpMqttBrokerDirectories(secretDir, publicDir, daysExpiry)

	agents := []string{ // agents always set up
		"cloudadapter-agent"}

	uccFlagPath := "/etc/intel-manageability/public/ucc_flag"
	if content, err := ioutil.ReadFile(uccFlagPath); err == nil &&
		strings.TrimSpace(string(content)) == "TRUE" {
		// append UCC specific agents
		agents = append(agents, "ucc-native-service")
	} else {
		// append agents only installed when not in UCC mode
		agents = append(agents, "dispatcher-agent", "telemetry-agent", "diagnostic-agent", "configuration-agent", "inbc-program", "cmd-program")
	}

	for _, each := range agents {
		setUpClientDirectories(secretDir, publicDir, daysExpiry, each)
	}
}

func createPrivateKey(keyFilePath string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		log.Fatalf("Unable to generate private key")
		os.Exit(1)
	}

	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privatePem, err := os.Create(keyFilePath)
	if err != nil {
		log.Fatalf("Unable to save private key")
		os.Exit(1)
	}

	if err = pem.Encode(privatePem, privateKeyBlock); err != nil {
		log.Fatalf("error encoding private pem: %s", err)
		os.Exit(1)
	}
}

// setUpClientDirectories sets up public/private keys for a given client (e.g., dispatcher-agent)
func setUpClientDirectories(secretDir string, publicDir string, daysExpiry string, client string) {
	clientSecretDir := filepath.Join(secretDir, client)
	mkDirIfNotExist(clientSecretDir, 0750) // TODO: implement group permission

	clientSecretKeyFilename := filepath.Join(clientSecretDir, client+".key")
	createPrivateKey(clientSecretKeyFilename)

	clientSecretCsrFilename := filepath.Join(clientSecretDir, client+".csr")
	cmd := exec.Command("openssl", "req", "-new", "-key", clientSecretKeyFilename,
		"-subj", "/C=US/ST=Oregon/L=Hillsboro/O=Intel/OU=EVAL/CN="+client, "-out",
		clientSecretCsrFilename)
	mustRunCmd(cmd)

	mqttCaSecretKeyFilename := filepath.Join(secretDir, "mqtt-ca", "mqtt-ca.key")
	mqttCaSecretCrtFilename := filepath.Join(secretDir, "mqtt-ca", "mqtt-ca.crt")
	clientSecretCrtFilename := filepath.Join(clientSecretDir, client+".crt")
	cmd = exec.Command("openssl", "x509", "-req", "-days", daysExpiry, "-sha384", "-extensions",
		"v3_req", "-CA", mqttCaSecretCrtFilename, "-CAkey",
		mqttCaSecretKeyFilename, "-CAcreateserial", "-in",
		clientSecretCsrFilename, "-out", clientSecretCrtFilename)
	mustRunCmd(cmd)

	clientPublicDir := filepath.Join(publicDir, client)
	mkDirIfNotExist(clientPublicDir, 0755)

	clientPublicCrtFilename := filepath.Join(clientPublicDir, client+".crt")
	must(copyFile(clientSecretCrtFilename, clientPublicCrtFilename),
		"Copying "+clientSecretCrtFilename+" to "+clientPublicCrtFilename)
}

// setUpMqttBrokerDirectories sets up private/public directories for the MQTT broker
func setUpMqttBrokerDirectories(secretDir string, publicDir string, daysExpiry string) {
	mqttBrokerSecretDir := filepath.Join(secretDir, "mqtt-broker")
	mkDirIfNotExist(mqttBrokerSecretDir, 0750)
	mqttBrokerSecretKeyFilename := filepath.Join(mqttBrokerSecretDir, "mqtt-broker.key")
	createPrivateKey(mqttBrokerSecretKeyFilename)

	opensslSanCnf := []byte(`[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost

[req_distinguished_name]
`)
	opensslSanSecretCnfFilename := filepath.Join(mqttBrokerSecretDir, "openssl-san.cnf")
	err := ioutil.WriteFile(opensslSanSecretCnfFilename, opensslSanCnf, 0600)
	must(err, "Write "+opensslSanSecretCnfFilename)

	mqttBrokerSecretCsrFilename := filepath.Join(mqttBrokerSecretDir, "mqtt-broker.csr")
	cmd := exec.Command("openssl", "req", "-new", "-out", mqttBrokerSecretCsrFilename,
		"-key", mqttBrokerSecretKeyFilename, "-config", opensslSanSecretCnfFilename, "-subj",
		"/C=US/ST=Oregon/L=Hillsboro/O=Intel/OU=EVAL/CN=localhost")
	mustRunCmd(cmd)

	mqttCaSecretKeyFilename := filepath.Join(secretDir, "mqtt-ca", "mqtt-ca.key")
	mqttBrokerSecretCrtFilename := filepath.Join(mqttBrokerSecretDir, "mqtt-broker.crt")
	mqttCaSecretCrtFilename := filepath.Join(secretDir, "mqtt-ca", "mqtt-ca.crt")
	cmd = exec.Command("openssl", "x509", "-req", "-days", daysExpiry, "-sha384", "-extensions",
		"v3_req", "-CA", mqttCaSecretCrtFilename, "-CAkey",
		mqttCaSecretKeyFilename, "-CAcreateserial", "-in",
		mqttBrokerSecretCsrFilename,
		"-out", mqttBrokerSecretCrtFilename)
	mustRunCmd(cmd)

	mqttBrokerPublicDir := filepath.Join(publicDir, "mqtt-broker")
	mkDirIfNotExist(mqttBrokerPublicDir, 0755)

	mqttBrokerPublicCrtFilename := filepath.Join(mqttBrokerPublicDir, "mqtt-broker.crt")
	must(copyFile(mqttBrokerSecretCrtFilename, mqttBrokerPublicCrtFilename),
		"Copying "+mqttBrokerSecretCrtFilename+" to "+mqttBrokerPublicCrtFilename)
}

// setUpMqttCaDirectories sets up private/public directories for the MQTT Certificate Authority
func setUpMqttCaDirectories(secret_dir string, public_dir string, days_expiry string) {
	mqttCaSecretDir := filepath.Join(secret_dir, "mqtt-ca")
	mkDirIfNotExist(mqttCaSecretDir, 0750)

	mqttCaSecretKeyFilename := filepath.Join(mqttCaSecretDir, "mqtt-ca.key")
	createPrivateKey(mqttCaSecretKeyFilename)

	mqttCaSecretCsrFilename := filepath.Join(mqttCaSecretDir, "mqtt-ca.csr")
	cmd := exec.Command("openssl", "req", "-new", "-key", mqttCaSecretKeyFilename,
		"-subj", "/C=US/ST=Oregon/L=Hillsboro/O=Intel/OU=EVAL/CN=mqtt-ca.example.com", "-out",
		mqttCaSecretCsrFilename)
	mustRunCmd(cmd)

	mqttCaSecretCrtFilename := filepath.Join(mqttCaSecretDir, "mqtt-ca.crt")
	cmd = exec.Command("openssl", "x509", "-req", "-days", days_expiry, "-sha384", "-extensions",
		"v3-ca", "-signkey", mqttCaSecretKeyFilename, "-in",
		mqttCaSecretCsrFilename, "-out", mqttCaSecretCrtFilename)
	mustRunCmd(cmd)

	mqttCaPublicDir := filepath.Join(public_dir, "mqtt-ca")
	mkDirIfNotExist(mqttCaPublicDir, 0755)

	mqttCaPublicCrtFilename := filepath.Join(mqttCaPublicDir, "mqtt-ca.crt")
	must(copyFile(mqttCaSecretCrtFilename, mqttCaPublicCrtFilename),
		"Copying "+mqttCaSecretCrtFilename+" to "+mqttCaPublicCrtFilename)
}
