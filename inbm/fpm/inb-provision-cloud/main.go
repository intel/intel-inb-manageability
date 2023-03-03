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
	"strings"
	"strconv"

	"github.com/google/uuid"
	schema "github.com/lestrrat-go/jsschema"
	"github.com/lestrrat-go/jsschema/validator"
)

func usage() {
	_, _ = fmt.Fprintf(os.Stderr, "usage: inb-provision-cloud [cloud credential directory]"+
		"[thingsboard template directory] [generic json schema file]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) < 3 {
		log.Fatalln("Please specify cloud credential directory, ThingsBoard template directory, " +
			"and path to generic JSON schema")
	}

	cloudCredentialDir, err := filepath.Abs(args[0])
	must(err, "Getting absolute cloud credential directory")

	thingsBoardTemplateDir, err := filepath.Abs(args[1])
	must(err, "Getting ThingsBoard template directory")

	jsonSchemaFile, err := filepath.Abs(args[2])
	must(err, "Getting generic JSON schema file")

	cloudCredentialDirExists, _ := isDir(cloudCredentialDir)
	if !cloudCredentialDirExists {
		log.Fatalf("Cloud credential directory does not exist: %s\n", cloudCredentialDir)
	}

	thingsBoardTemplateDirExists, _ := isDir(thingsBoardTemplateDir)
	if !thingsBoardTemplateDirExists {
		log.Fatalf("ThingsBoard template directory does not exist: %s\n", thingsBoardTemplateDir)
	}

	jsonSchemaFileExists := fileExists(jsonSchemaFile)
	if !jsonSchemaFileExists {
		log.Fatalf("JSON schema file does not exist: %s\n", jsonSchemaFile)
	}

	setUpCloudCredentialDirectory(cloudCredentialDir, thingsBoardTemplateDir, jsonSchemaFile)
}

// setUpCloudCredentialDirectory prompts the user for information to connect to a cloud and sets up the cloud
func setUpCloudCredentialDirectory(cloudCredentialDir string, thingsBoardTemplateDir string, jsonSchemaFile string) {
	cloudFile := "adapter.cfg" // The main config file
	cloudFilePath := filepath.Join(cloudCredentialDir, filepath.Clean(cloudFile))
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
		[]string{"Telit Device Cloud", "Azure IoT Central", "ThingsBoard", "Custom"})
	cloudConfig := ""
	switch selection {
	case "Telit Device Cloud":
		cloudConfig = configureTelit()
	case "Azure IoT Central":
		cloudConfig = configureAzure()
	case "ThingsBoard":
		cloudConfig = configureThingsBoard(cloudCredentialDir, thingsBoardTemplateDir)
	case "Custom":
		cloudConfig = configureCustom(jsonSchemaFile)
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

func configureTelit() string {
	println("\nConfiguring to use Telit...")
	telitHost := "x"
	telitPort := "8883"
	devTelit := "api-dev.devicewise.com"
	productionTelit := "api.devicewise.com"

	println()
	prodTelitChoice := "Production (" + productionTelit + ")"
	devTelitChoice := "Development (" + devTelit + ")"
	env := promptSelect("Please select the Telit host to use:",
		[]string{prodTelitChoice, devTelitChoice})

	switch env {
	case prodTelitChoice:
		telitHost = productionTelit
	case devTelitChoice:
		telitHost = devTelit
	default:
		log.Fatalf("Internal error: selection prompt returned invalid option")
	}

	telitToken := promptString("Provide Telit token (Hint: https://wiki.ith.intel.com/display/TRTLCRK/Connecting+to+Helix+Device+Cloud):")
	telitKey := promptString("Provide Telit Thing Key (leave blank to autogenerate):")
	if telitKey == "" {
		telitKey = uuid.New().String()
	}

	println("Thing key: " + telitKey)

	return makeTelitJson(telitHost, telitPort, telitKey, telitToken)
}

func makeTelitJson(telitHost string, telitPort string, telitKey string, telitToken string) string {
	return `{ "cloud": "telit", "config": { "hostname": "` + telitHost + `", "port": ` + telitPort + `, "key": "` +
		telitKey + `", "token": "` + telitToken + `" } }`
}

func configureCustom(jsonSchemaFile string) string {
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
		s, err := schema.ReadFile(jsonSchemaFile)
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

func configureAzure() string {
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
			cloudCredentialPublicDir, err := filepath.Abs("/etc/intel-manageability/public/cloudadapter-agent/")
			must(err, "Getting absolute cloud public directory")
			cloudCredentialSecretDir, err := filepath.Abs("/etc/intel-manageability/secret/cloudadapter-agent/")
			must(err, "Getting absolute cloud credential directory")

			deviceCertPath = filepath.Join(cloudCredentialPublicDir, "device_cert.pem")
			deviceKeyPath = filepath.Join(cloudCredentialSecretDir, "device_key.pem")

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

func configureThingsBoard(cloudCredentialDir string, thingsBoardTemplateDir string) string {
	println("\nConfiguring to use ThingsBoard...")

	serverIp := promptString("\nPlease enter the server IP:")
	if net.ParseIP(serverIp) == nil {
		log.Fatalf("Invalid IP address provided.")
	}

	serverPort := promptString("\nPlease enter the server port (default 1883):")
	if serverPort == "" {
		serverPort = "1883"
	} else {
		portNum, err := strconv.Atoi(serverPort)
		if ( err != nil || portNum > 65535 || portNum < 1) {
			log.Fatalf("Invalid port number provided.")
		}
	}

	selection := promptSelect("Please choose provision type.",
		[]string{"Token authentication", "X509 authentication"})
	deviceToken := ""
	deviceCertPath := ""
	configureTls := false
	thingsBoardJsonTemplate := ""
	caPath := ""
	switch selection {
	case "Token authentication":
		deviceToken = promptString("\nPlease enter the device token:")
		configureTls = promptYesNo("\nConfigure TLS?")
	case "X509 authentication":
		println("\nConfiguring device to use X509 auth requires device certificate verification.\n")
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
			println("\nConfiguring TLS.")
			configureTls = true
		} else {
			log.Fatalf("\nPlease generate the device certs and keys prior to provisioning the device to Thingsboard using X509 auth.")
		} 
	default:
		log.Fatalf("Internal error: selection prompt returned invalid option for authentication type.")
	}
	
	if configureTls {
		// Write a ThingsBoard CA file
		caPath = filepath.Join(cloudCredentialDir, "thingsboard.pub.pem")
		data := []byte{}
		if promptYesNo("\nInput ThingsBoard CA from file?") {
			data = promptFile("\nThingsBoard CA file (*.pub.pem)")
		} else {
			println("\nInput contents of ThingsBoard CA file (*.pub.pem)")
			data = []byte(readMultilineString())
		}
		err := ioutil.WriteFile(caPath, data, 0640)
		if err != nil {
			log.Fatalf("Error writing to " + caPath)
		}

		thingsBoardJsonFile := filepath.Join(filepath.Clean(thingsBoardTemplateDir), "config_tls.json.template")
		thingsBoardJsonBytes, err := ioutil.ReadFile(filepath.Clean(thingsBoardJsonFile))
		if err != nil {
			log.Fatalf("Error reading from " + thingsBoardJsonFile)
		}
		thingsBoardJsonTemplate = string(thingsBoardJsonBytes)

	} else {
		// Use the unencrypted ThingsBoard template
		thingsBoardJsonFile := filepath.Join(thingsBoardTemplateDir, "config.json.template")
		thingsBoardJsonBytes, err := ioutil.ReadFile(filepath.Clean(thingsBoardJsonFile))
		if err != nil {
			log.Fatalf("Error reading from " + thingsBoardJsonFile)
		}
		thingsBoardJsonTemplate = string(thingsBoardJsonBytes)
	}

	return makeThingsboardJson(thingsBoardJsonTemplate, caPath, deviceToken, serverIp, serverPort, deviceCertPath)
}

func makeThingsboardJson(template string, caPath string, deviceToken string, serverIp string, serverPort string, deviceCertPath string) string {
	thingsboardConfigJson := template
	thingsboardConfigJson = strings.Replace(thingsboardConfigJson, "{CA_PATH}", caPath, -1)
	thingsboardConfigJson = strings.Replace(thingsboardConfigJson, "{TOKEN}", deviceToken, -1)
	thingsboardConfigJson = strings.Replace(thingsboardConfigJson, "{HOSTNAME}", serverIp, -1)
	thingsboardConfigJson = strings.Replace(thingsboardConfigJson, "{PORT}", serverPort, -1)
	thingsboardConfigJson = strings.Replace(thingsboardConfigJson, "{CLIENT_CERT_PATH}", deviceCertPath, -1)

	return `{ "cloud": "thingsboard", "config": ` + thingsboardConfigJson + ` }`
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
