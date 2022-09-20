package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {

	certPEMBlock, err := ioutil.ReadFile("Milan.pem")
	if err != nil {
		log.Fatal(err)
	}

	var blocks [][]byte
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			blocks = append(blocks, certDERBlock.Bytes)
		}
	}

	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block)
		if err != nil {
			log.Println(err)
			continue
		}

		fmt.Println("Certificate:")
		fmt.Printf("\tSubject: %+v\n", cert.Subject)
		fmt.Printf("\tDNS Names: %+v\n", cert.DNSNames)
		fmt.Printf("\tEmailAddresses: %+v\n", cert.EmailAddresses)
		fmt.Printf("\tIPAddresses: %+v\n", cert.IPAddresses)
	}

}
