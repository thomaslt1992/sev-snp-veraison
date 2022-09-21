// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/go-plugin"
	"github.com/veraison/services/proto"
	"github.com/veraison/services/scheme"
)

type Scheme struct{}

func (s Scheme) GetName() string {
	return proto.AttestationFormat_SEV_SNP.String()
}

func (s Scheme) GetFormat() proto.AttestationFormat {
	return proto.AttestationFormat_SEV_SNP
}

func (s Scheme) GetSupportedMediaTypes() []string {
	return []string{
		"application/sev-snp-attestation-token",
	}
}

func (s Scheme) SynthKeysFromSwComponent(tenantID string, swComp *proto.Endorsement) ([]string, error) {
	return synthKeysFromParts("software component", tenantID, swComp.GetAttributes())
}

func (s Scheme) SynthKeysFromTrustAnchor(tenantID string, ta *proto.Endorsement) ([]string, error) {
	return synthKeysFromParts("trust anchor", tenantID, ta.GetAttributes())
}

func (s Scheme) GetTrustAnchorID(token *proto.AttestationToken) (string, error) {
	if token.Format != proto.AttestationFormat_SEV_SNP {
		return "", fmt.Errorf("wrong format: expect %q, but found %q",
			proto.AttestationFormat_SEV_SNP.String(),
			token.Format.String(),
		)
	}

	var decoded ExtendedAttestationReport

	if err := decoded.Decode(token.Data); err != nil {
		return "", err
	}
	//build tsId based on the product extracted from the certificate
	var taId string
	for _, val := range decoded.report.chip_id {
		chipId = chipId + fmt.Sprintf("%x", val) //strconv.FormatUint(val, 16)

	}

	return taId, nil
}

func (s Scheme) ExtractVerifiedClaims(token *proto.AttestationToken, trustAnchor string) (*scheme.ExtractedClaims, error) {
	if token.Format != proto.AttestationFormat_SEV_SNP {
		return nil, fmt.Errorf("wrong format: expect %q, but found %q",
			proto.AttestationFormat_SEV_SNP.String(),
			token.Format.String(),
		)
	}

	var decodedReport Token

	if err := decodedReport.decodeCertificate(token.Data); err != nil {
		return nil, fmt.Errorf("could not decode token certificates: %w", err)
	}

	var cert x509.Certificate = parseCertificate(trustAnchor)

	rootCert = decoded.getArkCertificate()

	if !cert.equal(rootCert) {
		return nil, fmt.Errorf("wrong ARK certificate")
	}

	//verify report's certificates chain
	if err := decoded.verifyCertificates(); err != nil {
		return nil, fmt.Errorf("certificates chain verification failed: %w", err)
	}

	pubKey, err := decoded.getVcekPublicKey()
	if err != nil {
		return nil, fmt.Errorf("could not parse trust anchor: %w", err)
	}

	if err = decoded.verifySignature(pubKey); err != nil {
		return nil, fmt.Errorf("could not verify token signature: %w", err)
	}

	evidence := scheme.NewExtractedClaims()
	evidence.ClaimsSet["imageId"] = decoded.attestation_report.image_id
	evidence.ClaimsSet["guest-svn"] = decoded.attestation_report.guest_svn
	evidence.ClaimsSet["measurement"] = decoded.attestation_report.measurement

	return evidence, nil
}

func (s Scheme) AppraiseEvidence(ec *proto.EvidenceContext, endorsementStrings []string) (*proto.AppraisalContext, error) {
}

func parseKey(keyString string) (*ecdsa.PublicKey, error) {
	buf, err := base64.StdEncoding.DecodeString(keyString)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key: %v", err)
	}

	ret, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("could not extract EC public key; got [%T]: %v", key, err)
	}

	return ret, nil
}

func main() {
	var handshakeConfig = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "VERAISON_PLUGIN",
		MagicCookieValue: "VERAISON",
	}

	var pluginMap = map[string]plugin.Plugin{
		"scheme": &scheme.Plugin{
			Impl: &Scheme{},
		},
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins:         pluginMap,
	})
}
