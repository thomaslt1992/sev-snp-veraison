package main

import (
	"crypto/ecdsa"

	"github.com/google/go-tpm/tpm2"
)

// Token is the container for the decoded token in SEV-SNP environment
type Token struct {
	attestationReport ExtendedAttestationReport
	signature         *tpm2.Signature
}

type ExtendedAttestationReport struct {
	report AttestationReport
	VCEK   CertificateTable
	ASK    CertificateTable
	ARK    CertificateTable
}

type CertificateTable struct {
	Certificate struct {
		guid   [16]uint32
		offset uint32
		length uint32
	}
	certificateTableEmpty []uint32
}

//TODO: Check the Union it must be either struct or a raw
type TcbVersion struct {
	TcbUnion *struct {
		boot_loader uint8
		tee         uint8
		reserved    [4]uint8
		snp         uint8
		microcode   uint8
	}
	raw *uint64
}

type AttestationReport struct {
	version           uint32
	guest_svn         uint32
	policy            uint64
	family_id         [16]uint8
	image_id          [16]uint8
	vpml              uint32
	signatureAlgo     uint32
	platform_version  TcbVersion
	platform_info     uint64
	flags             uint32
	reserved0         uint32
	report_data       [64]uint8
	measurement       [48]uint8
	host_data         [32]uint8
	id_key_digest     [48]uint8
	author_key_digest [48]uint8
	report_id         [32]uint8
	report_id_ma      [32]uint8
	reported_tcb      TcbVersion
	reserved1         [24]uint8
	chip_id           [64]uint8
	reserved2         [192]uint8
	signature         *tpm2.Signature
}

type MsgReportResponse struct {
	status      uint32
	report_size uint32
	reserved    [0x20 - 0x8]uint8
	report      AttestationReport
}

func (t Token) VerifySignature(key *ecdsa.PublicKey) error {
	return nil
}
