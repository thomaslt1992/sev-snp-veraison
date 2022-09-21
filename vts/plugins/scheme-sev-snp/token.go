package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// Token is the container for the decoded token in SEV-SNP environment
type Token struct {
	AttestationReport ExtendedAttestationReport
	Signature         *tpm2.Signature
	Raw               []byte
}

type ExtendedAttestationReport struct {
	report AttestationReport
	VCEK   x509.Certificate
	ASK    x509.Certificate
	ARK    x509.Certificate
}

type TcbVersion struct {
	// This is a simulation of a union in golang
	// we applied the * memory pointer that makes this struct work
	// as described:
	// either a struct is given as input or a raw string
	// The allocation of memory is handled with the pointer
	TcbUnion *struct {
		bootLoader uint8
		tee        uint8
		reserved   [4]uint8
		snp        uint8
		microcode  uint8
	}
	raw *uint64
}

type AttestationReport struct {
	version         uint32
	guestSvn        uint32
	policy          uint64
	familyId        [16]uint8
	imageId         [16]uint8
	vpml            uint32
	signatureAlgo   uint32
	platformVersion TcbVersion
	platformInfo    uint64
	flags           uint32
	reserved0       uint32
	ReportData      [64]uint8
	measurement     [48]uint8
	hostData        [32]uint8
	idKeyDigest     [48]uint8
	authorKeyDigest [48]uint8
	reportId        [32]uint8
	reportIdMa      [32]uint8
	reportedTcb     TcbVersion
	reserved1       [24]uint8
	chipId          [64]uint8
	reserved2       [192]uint8
}

type MsgReportResponse struct {
	status      uint32
	report_size uint32
	reserved    [0x20 - 0x8]uint8
	report      AttestationReport
}

func main() {

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		DNSName: "kdsintf.amd.com",
		Roots:   roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}
}

func DecodeAttestationData(j map[string]interface{}) {
	for k, v := range j {
		fmt.Printf("%v %v\n", k, v)
	}
}

func (t Token) VerifySignature(key *ecdsa.PublicKey) error {
	digest := sha256.Sum256(t.Raw)

	if !ecdsa.Verify(key, digest[:], t.Signature.ECC.R, t.Signature.ECC.S) {
		return fmt.Errorf("Failed to verify th signature")
	}

	return nil
}
