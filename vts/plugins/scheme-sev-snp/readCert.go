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

	certAsk, err := x509.ParseCertificate(blocks[0])
	if err != nil {
		fmt.Println(err)

	}

	certArk, err := x509.ParseCertificate(blocks[1])
	if err != nil {
		fmt.Println(err)

	}

	err1 := certAsk.CheckSignatureFrom(certArk)
	if err != nil {
		fmt.Printf("\tSignature verification error: %+v\n", err1)
	} else {
		fmt.Println("Ask certificate signature by Ark verified")
	}
}
