/*
@copyright: Copyright 2017-2023 Intel Corporation All Rights Reserved.
@license: Intel, see licenses/LICENSE for more details.
*/

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/uuid"
	schema "github.com/lestrrat-go/jsschema"
	"github.com/lestrrat-go/jsschema/validator"
)

const thingsboard string = "thingsboard"
const ucc string = "ucc"

func usage() {
	_, _ = fmt.Fprintf(os.Stderr, "usage: inb-provision-cloud [cloud credential directory]"+
		"[thingsboard template directory] [ucc template directory] [generic json schema file]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	var uccClientIdFile string
	var uccServerIdFile string
	var cloudCredentialPublicDir string
	var cloudCredentialSecretDir string

	if runtime.GOOS == "windows" {
		uccClientIdFile = "c:\\intel-manageability\\inbm\\etc\\ucc\\client_id"
		uccServerIdFile = "c:\\intel-manageability\\inbm\\etc\\ucc\\server_id"
		cloudCredentialPublicDir = "c:\\intel-manageability\\public\\cloudadapter-agent\\"
		cloudCredentialSecretDir = "c:\\intel-manageability\\secret\\cloudadapter-agent\\"
	} else {
		uccClientIdFile = "/etc/ucc/client_id"
		uccServerIdFile = "/etc/ucc/server_id"
		cloudCredentialPublicDir = "/etc/intel-manageability/public/cloudadapter-agent/"
		cloudCredentialSecretDir = "/etc/intel-manageability/secret/cloudadapter-agent/"
	}

	cloudCredentialPublicDir, err := filepath.Abs(cloudCredentialPublicDir)
	must(err, "Getting absolute cloud public directory")
	cloudCredentialSecretDir, err = filepath.Abs(cloudCredentialSecretDir)
	must(err, "Getting absolute cloud credential directory")

	args := flag.Args()
	if len(args) < 3 {
		log.Fatalln("Please specify cloud credential directory, ThingsBoard template directory, UCC " +
			"template directory, and path to generic JSON schema")
	}

	cloudCredentialDir, err := filepath.Abs(args[0])
	must(err, "Getting absolute cloud credential directory")

	thingsBoardTemplateDir, err := filepath.Abs(args[1])
	must(err, "Getting ThingsBoard template directory")

	uccTemplateDir, err := filepath.Abs(args[2])
	must(err, "Getting UCC template directory")

	jsonSchemaFile, err := filepath.Abs(args[3])
	must(err, "Getting generic JSON schema file")

	cloudCredentialDirExists, _ := isDir(cloudCredentialDir)
	if !cloudCredentialDirExists {
		log.Fatalf("Cloud credential directory does not exist: %s\n", cloudCredentialDir)
	}

	thingsBoardTemplateDirExists, _ := isDir(thingsBoardTemplateDir)
	if !thingsBoardTemplateDirExists {
		log.Fatalf("ThingsBoard template directory does not exist: %s\n", thingsBoardTemplateDir)
	}

	uccTemplateDirExists, _ := isDir(uccTemplateDir)
	if !uccTemplateDirExists {
		log.Fatalf("UCC template directory does not exist: %s\n", uccTemplateDir)
	}

	jsonSchemaFileExists := fileExists(jsonSchemaFile)
	if !jsonSchemaFileExists {
		log.Fatalf("JSON schema file does not exist: %s\n", jsonSchemaFile)
	}

	config := CloudConfig{
		CloudCredentialDir:       cloudCredentialDir,
		ThingsBoardTemplateDir:   thingsBoardTemplateDir,
		UccTemplateDir:           uccTemplateDir,
		JsonSchemaFile:           jsonSchemaFile,
		UccClientIdFile:          uccClientIdFile,
		UccServerIdFile:          uccServerIdFile,
		CloudCredentialPublicDir: cloudCredentialPublicDir,
		CloudCredentialSecretDir: cloudCredentialSecretDir,
	}

	setUpCloudCredentialDirectory(config)
}

type CloudConfig struct {
	CloudCredentialDir       string
	ThingsBoardTemplateDir   string
	UccTemplateDir           string
	JsonSchemaFile           string
	UccClientIdFile          string
	UccServerIdFile          string
	CloudCredentialPublicDir string
	CloudCredentialSecretDir string
}

// setUpCloudCredentialDirectory prompts the user for information to connect to a cloud and sets up the cloud
func setUpCloudCredentialDirectory(config CloudConfig) {
	cloudFile := "adapter.cfg" // The main config file
	cloudFilePath := filepath.Join(config.CloudCredentialDir, filepath.Clean(cloudFile))
	if fileExists(cloudFilePath) {
		if !confirmReplaceConfiguration(cloudFilePath) {
			os.Exit(0)
		} else {
			if os.Remove(cloudFilePath) != nil {
				log.Fatalf("Cannot remove existing cloud configuration.")
			}
		}
	}

	println()
	selection := promptSelect("Please choose a cloud service to use.",
		[]string{"Azure IoT Central", "ThingsBoard", "UCC", "Custom"})
	cloudConfig := ""
	switch selection {
	case "Azure IoT Central":
		cloudConfig = configureAzure(config)
	case "ThingsBoard":
		cloudConfig = configureThingsBoard(config)
	case "UCC":
		cloudConfig = configureUcc(config)
	case "Custom":
		cloudConfig = configureCustom(config)
	default:
		log.Fatalf("Internal error: selection prompt returned invalid option")
	}

	println("Cloud config: " + cloudConfig)

	err := ioutil.WriteFile(cloudFilePath, []byte(cloudConfig), 0640)
	if err != nil {
		log.Fatalf("Error writing new config to " + cloudFilePath)
	}
	println("Successfully configured cloud service!")
}

func configureCustom(config CloudConfig) string {
	println("\nConfiguring to use a custom cloud service...")
	name := promptString("Please enter a name for the cloud service:")

	json := []byte{}
	for len(json) == 0 {
		if promptYesNo("Input custom JSON from file?") {
			json = promptFile("custom JSON file")
		} else {
			println("Input custom JSON:")
			json = []byte(readMultilineString())
		}
		s, err := schema.ReadFile(config.JsonSchemaFile)
		if err != nil {
			log.Fatalf("Unable to read generic JSON schema")
		}
		v := validator.New(s)
		if err := v.Validate(json); err != nil {
			log.Fatalf("Failed to validate JSON configuration")
		}
	}

	return makeCustomJson(name, string(json))
}

func makeCustomJson(name string, json string) string {
	return `{ "cloud": "custom: ` + name + `", "config": ` + json + ` }`
}

func configureAzure(config CloudConfig) string {
	println("\nConfiguring to use Azure...")

	scopeId := promptString("Please enter the device Scope ID (" +
		"Hint: https://docs.microsoft.com/en-us/azure/iot-central/howto-generate-connection-string):")
	deviceId := promptString("Please enter the device ID (" +
		"Hint: https://docs.microsoft.com/en-us/azure/iot-central/howto-generate-connection-string):")
	deviceSasKey := ""
	deviceCertPath := ""
	deviceKeyPath := ""
	selection := promptSelect("Please choose provision type.",
		[]string{"SAS key authentication", "X509 authentication"})
	switch selection {
	case "SAS key authentication":
		deviceSasKey = promptString("Please enter the device SAS primary key (" +
			"Hint: https://docs.microsoft.com/en-us/azure/iot-central/howto-generate-connection-string")
	case "X509 authentication":
		println("\nConfiguring device to use X509 auth requires device certificate verification.\n")
		if promptYesNo("\nAre device certs and keys generated? ") {

			deviceCertPath = filepath.Join(config.CloudCredentialPublicDir, "device_cert.pem")
			deviceKeyPath = filepath.Join(config.CloudCredentialSecretDir, "device_key.pem")

			certData := []byte{}
			if promptYesNo("\nInput Device certificate from file?") {
				certData = promptFile("\nInput path to Device certificate file (*cert.pem)")
			} else {
				println("\nInput contents of Device certificate file (*cert.pem)")
				certData = []byte(readMultilineString())
			}
			certErr := ioutil.WriteFile(deviceCertPath, certData, 0644)
			if certErr != nil {
				log.Fatalf("Error writing to " + deviceCertPath)
			}

			keyData := []byte{}
			if promptYesNo("\nInput Device Key from file?") {
				keyData = promptFile("\nInput path to Device Key file (*key.pem)")
			} else {
				println("\nInput contents of Device certificate file (*key.pem)")
				keyData = []byte(readMultilineString())
			}
			keyErr := ioutil.WriteFile(deviceKeyPath, keyData, 0640)
			if keyErr != nil {
				log.Fatalf("Error writing to " + deviceKeyPath)
			}
		} else {
			log.Fatalf("\nPlease generate the device certs and keys prior to provisioning the device to Azure using X509 auth.")
		}
	default:
		log.Fatalf("Internal error: selection prompt returned invalid option for authentication type.")
	}

	return makeAzureJson(scopeId, deviceId, deviceCertPath, deviceKeyPath, deviceSasKey)
}

func makeAzureJson(scopeId string, deviceId string, deviceCertPath string, deviceKeyPath string, deviceSasKey string) string {
	return `{ "cloud": "azure", "config": { "scope_id": "` + scopeId +
		`", "device_id": "` + deviceId + `", "device_cert": "` + deviceCertPath + `", "device_key": "` + deviceKeyPath + `", "device_sas_key": "` + deviceSasKey + `" } }`
}

func configureThingsBoard(config CloudConfig) string {
	println("\nConfiguring to use ThingsBoard...")

	serverIp := getServerIp()
	serverPort := getServerPort("1883", "")

	doConfigureTls, deviceToken, deviceCertPath, _ := provisionToCloud(config.CloudCredentialDir, thingsboard)
	jsonTemplate := ""
	caPath := ""

	if doConfigureTls {
		jsonTemplate, caPath = configureTls(config.ThingsBoardTemplateDir, "thingsboard.pub.pem",
			"ThingsBoard", config.CloudCredentialDir)
	} else {
		jsonTemplate = createUnencryptedTemplate(config.ThingsBoardTemplateDir)
	}

	return makeCloudJson(thingsboard, jsonTemplate, caPath, deviceToken, serverIp,
		serverPort, deviceCertPath, "", "", "", "", "")
}

func configureUcc(config CloudConfig) string {
	println("\nConfiguring to use UCC...")

	if !fileExists(config.UccClientIdFile) {
		log.Fatalf("Client ID file (%s) is missing. Unable to provision for UCC.", config.UccClientIdFile)
	}
	if !fileExists(config.UccServerIdFile) {
		log.Fatalf("Server ID file (%s) is missing. Unable to provision for UCC.", config.UccServerIdFile)
	}

	serverIp := getServerIp()
	serverPort := getServerPort("1883", "")
	doConfigureTls, deviceToken, deviceCertPath, deviceKeyPath := provisionToCloud(config.CloudCredentialDir, "ucc")
	jsonTemplate := ""
	caPath := ""

	if doConfigureTls {
		jsonTemplate, caPath = configureTls(config.UccTemplateDir, "ucc.ca.pem.crt",
			ucc, config.CloudCredentialDir)
	} else {
		jsonTemplate = createUnencryptedTemplate(config.UccTemplateDir)
	}

	clientId := getIdFromFile(config.UccClientIdFile)
	if !isClientIdValid(clientId) {
		log.Fatalf("UCC Client ID does not meet the requirements.  Unable to provision for UCC.")
	}

	serverId := getIdFromFile(config.UccServerIdFile)
	if !isServerIdValid(serverId) {
		log.Fatalf("UCC Server ID does not meet the requirements.  Unable to provision for UCC.")
	}

	proxyHostName, proxyPort := configureProxy()
	return makeCloudJson(ucc, jsonTemplate, caPath, deviceToken, serverIp, serverPort, deviceCertPath, deviceKeyPath,
		proxyHostName, proxyPort, clientId, serverId)
}

func getIdFromFile(filepath string) string {
	if content, err := ioutil.ReadFile(filepath); err == nil {
		return strings.TrimSpace(string(content))
	}
	log.Fatalf("Unable to read id from " + filepath + ".  Unable to provision for UCC.")
	return ""
}

func isClientIdValid(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		log.Println("Client ID Length is greater than 128 characters.  Unable to provision for UCC.")
		return false
	}
	if strings.ContainsAny(id, "# + \x00") {
		log.Println("Client ID contains invalid characters.  Unable to provision for UCC.")
		return false
	}
	return true
}

func isServerIdValid(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		log.Println("Server ID Length is greater than 128 characters.  Unable to provision for UCC.")
		return false
	}
	if _, err := uuid.Parse(id); err == nil {
		return true
	}
	if net.ParseIP(id) == nil {
		log.Println("Server ID doesn't contain a valid (UUID or IP). Unable to provision for UCC.")
		return false
	}
	return true
}

func configureProxy() (string, string) {
	hostName := ""
	port := ""
	if promptYesNo("\nConfigure a proxy? ") {
		hostName = promptString("\nPlease enter the proxy server hostname or IP:")
		port = getServerPort("911", "proxy")
	}

	return hostName, port
}

func createUnencryptedTemplate(templateDir string) string {
	jsonFile := filepath.Join(templateDir, "config.json.template")
	jsonBytes, err := ioutil.ReadFile(filepath.Clean(jsonFile))
	if err != nil {
		log.Fatalf("Error reading from " + jsonFile)
	}
	return string(jsonBytes)
}

func getServerIp() string {
	serverIPName := promptString("\nPlease enter the server IP or hostname:")
	if !isValidIpAddress(serverIPName) {
		if !isValidHostname(serverIPName) {
			log.Fatalf("Invalid Hostname or IP address provided.")
		}
	}
	return serverIPName
}

func isValidIpAddress(ipaddr string) bool {
	if net.ParseIP(ipaddr) == nil {
		return false
	}
	return true
}

func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	validChars := regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
	return validChars.MatchString(hostname)
}

func getServerPort(defaultPort string, portType string) string {
	serverPort := promptString("\nPlease enter the " + portType + " server port (default " + defaultPort + "):")
	if serverPort == "" {
		serverPort = defaultPort
	} else {
		portNum, err := strconv.Atoi(serverPort)
		if err != nil || portNum > 65535 || portNum < 1 {
			log.Fatalf("Invalid port number provided.")
		}
	}
	return serverPort
}

func provisionToCloud(cloudCredentialDir string, cloudProviderName string) (bool, string, string, string) {
	// provision the device to the cloud
	selection := promptSelect("Please choose provision type.",
		[]string{"Token authentication", "X509 authentication"})

	deviceToken := ""
	doConfigureTls := false

	deviceCertPath := ""
	deviceKeyPath := ""
	switch selection {
	case "Token authentication":
		deviceToken = promptString("\nPlease enter the device token:")
		doConfigureTls = promptYesNo("\nConfigure TLS?")
	case "X509 authentication":
		doConfigureTls = true
		println("\nConfiguring device to use X509 auth requires device certificate verification.\n")
		if cloudProviderName == thingsboard {
			deviceCertPath = configureThingsboardX509(cloudCredentialDir)
		} else { // ucc
			deviceCertPath, deviceKeyPath = configureUccX509(cloudCredentialDir)
		}
	default:
		log.Fatalf("Internal error: selection prompt returned invalid option for authentication type.")
	}
	return doConfigureTls, deviceToken, deviceCertPath, deviceKeyPath
}

func configureUccX509(cloudCredentialDir string) (string, string) {
	deviceCertPath := ""
	deviceKeyPath := ""
	if promptYesNo("\nAre device certs and keys generated? ") {
		certData := []byte{}
		deviceCertPath = filepath.Join(cloudCredentialDir, "client.crt")
		if promptYesNo("\nInput Device certificate from file?") {
			certData = promptFile("\nInput path to Device certificate file (*.crt)")
		} else {
			println("\nInput contents of Device certificate file (*.crt)")
			certData = []byte(readMultilineString())
		}
		certErr := ioutil.WriteFile(deviceCertPath, certData, 0644)
		if certErr != nil {
			log.Fatalf("Error writing to " + deviceCertPath)
		}

		// Device Key
		keyData := []byte{}
		deviceKeyPath = filepath.Join(cloudCredentialDir, "client.key")
		if promptYesNo("\nInput Device key from file?") {
			keyData = promptFile("\nInput path to Device key file (*.key)")
		} else {
			println("\nInput contents of Device certificate file (*.key)")
			keyData = []byte(readMultilineString())
		}
		err := ioutil.WriteFile(deviceKeyPath, keyData, 0640)
		if err != nil {
			log.Fatalf("Error writing to " + deviceKeyPath)
		}
	} else {
		log.Fatalf("\nPlease generate the device certs and keys prior to provisioning the device to the cloud provider using X509 auth.")
	}
	return deviceCertPath, deviceKeyPath
}

func configureThingsboardX509(cloudCredentialDir string) string {
	// configure cloud provider for X509
	deviceCertPath := ""
	if promptYesNo("\nAre device certs and keys generated? ") {
		certData := []byte{}
		deviceCertPath = filepath.Join(cloudCredentialDir, "device.nopass.pem")
		if promptYesNo("\nInput Device certificate from file?") {
			certData = promptFile("\nInput path to Device certificate file (*nopass.pem)")
		} else {
			println("\nInput contents of Device certificate file (*nopass.pem)")
			certData = []byte(readMultilineString())
		}
		certErr := ioutil.WriteFile(deviceCertPath, certData, 0644)
		if certErr != nil {
			log.Fatalf("Error writing to " + deviceCertPath)
		}
	} else {
		log.Fatalf("\nPlease generate the device certs and keys prior to provisioning the device to the cloud provider using X509 auth.")
	}
	return deviceCertPath
}

func configureTls(templateDir string, caFileName string, cloudProviderName string, cloudCredentialDir string) (string, string) {
	// Write a CA file
	println("\nConfiguring TLS.")
	caPath := filepath.Join(cloudCredentialDir, caFileName)

	expectedFileType := "*.pub.pem"
	if cloudProviderName == ucc {
		expectedFileType = "*.pem.crt"
	}

	data := []byte{}
	if promptYesNo("\nInput " + cloudProviderName + " CA from file?") {
		data = promptFile("\n" + cloudProviderName + " CA file (" + expectedFileType + ")")
	} else {
		println("\nInput contents of " + " CA file (" + expectedFileType + ")")
		data = []byte(readMultilineString())
	}
	err := ioutil.WriteFile(caPath, data, 0640)
	if err != nil {
		log.Fatalf("Error writing to " + caPath)
	}

	jsonFile := filepath.Join(filepath.Clean(templateDir), "config_tls.json.template")
	jsonBytes, err := ioutil.ReadFile(filepath.Clean(jsonFile))
	if err != nil {
		log.Fatalf("Error reading from " + jsonFile)
	}
	return string(jsonBytes), caPath
}

func removeProxySection(template string) string {
	proxySection := `"proxy": {
        "hostname": "{PROXY_HOSTNAME}",
        "port": {PROXY_PORT}
    },`

	return strings.Replace(template, proxySection, "", 1)
}

func makeCloudJson(cloudProviderName string, template string, caPath string, deviceToken string, serverIp string,
	serverPort string, deviceCertPath string, deviceKeyPath string, proxyHostName string,
	proxyPort string, clientId string, serverId string) string {
	if proxyHostName == "" {
		template = removeProxySection(template)
	}

	configJson := template
	configJson = strings.Replace(configJson, "{CA_PATH}", caPath, -1)
	configJson = strings.Replace(configJson, "{TOKEN}", deviceToken, -1)
	configJson = strings.Replace(configJson, "{HOSTNAME}", serverIp, -1)
	configJson = strings.Replace(configJson, "{PORT}", serverPort, -1)
	configJson = strings.Replace(configJson, "{CLIENT_CERT_PATH}", deviceCertPath, -1)
	configJson = strings.Replace(configJson, "{CLIENT_KEY_PATH}", deviceKeyPath, -1)
	configJson = strings.Replace(configJson, "{PROXY_HOSTNAME}", proxyHostName, -1)
	configJson = strings.Replace(configJson, "{PROXY_PORT}", proxyPort, -1)
	configJson = strings.Replace(configJson, "{CLIENT_ID}", clientId, -1)
	configJson = strings.Replace(configJson, "{SERVER_ID}", serverId, -1)

	return `{ "cloud": "` + cloudProviderName + `", "config": ` + configJson + ` }`
}

func confirmReplaceConfiguration(cloudFilePath string) bool {
	cloudFileContents, err := ioutil.ReadFile(filepath.Clean(cloudFilePath))
	if err != nil {
		log.Fatalf("Cloud configuration already exists at " + cloudFilePath + ", but cannot be read.")
	}
	configurationMatches := regexp.MustCompile(`"cloud":\s*("[_\-\w:\s]+")`).FindAllSubmatch(cloudFileContents, -1)

	if len(configurationMatches) > 0 {
		println("A cloud configuration already exists: " + string(configurationMatches[0][1]))
	} else {
		println("Cloud configuration exists at " + cloudFilePath + ", but has an invalid format.")
	}
	return promptYesNo("Replace configuration?")
}
