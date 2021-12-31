/*

*/

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)


func usage() {
	_, _ = fmt.Fprintf(os.Stderr, "usage: inb-provision-ota-cert\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {

	if promptYesNo("\nSignature checks on OTA packages cannot not be validated without provisioning a cert file.\nDo you wish to use a pre-provisioned cert file for signature checks for OTA packages?") {
		dispatcherPublicDir, err := filepath.Abs("/etc/intel-manageability/public/dispatcher-agent/")
		must(err, "Getting absolute dispatcher agent credential directory")
		otaCertPath := filepath.Join(dispatcherPublicDir, "ota_signature_cert.pem")

		otaCertData := []byte{}
		if promptYesNo("\nInput OTA package certificate from file?") {
			otaCertData = promptFile("\nInput path to OTA package certificate file (*cert.pem)")
		} else {				println("\nInput contents of OTA package certificate file (*cert.pem)")
			otaCertData = []byte(readMultilineString())
		}
		otaCertErr := ioutil.WriteFile(otaCertPath, otaCertData, 0644)
		if otaCertErr != nil {
			log.Fatalf("Error writing to " + otaCertPath)
		}
	} else {
		println("\nProceeding without provisioning a cert file for OTA package authentication.")
	}
}
