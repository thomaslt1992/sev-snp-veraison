package main

// Token is the container for the decoded token in SEV-SNP environment
type Token struct {
	tcb_version        tcb_version
	attestation_report attestation_report
	// TODO: add certificates
}

type extended_attestation_report struct {
	report attestation_report
	//TODO: cert	certificate
}

type tcb_version struct {
	tcb_union struct {
		boot_loader *uint8
		tee         *uint8
		reserved    [4]*uint8
		snp         *uint8
		microcode   *uint8
	}
	raw uint64
}
type attestation_report struct {
	version           uint32
	guest_svn         uint32
	policy            uint64
	family_id         [16]uint8
	image_id          [16]uint8
	vpml              uint32
	signature_algo    uint32
	platform_version  tcb_version
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
	reported_tcb      tcb_version
	reserved1         [24]uint8
	chip_id           [64]uint8
	reserved2         [192]uint8
	signature         signature
}

type signature struct {
	r        [72]uint8
	s        [72]uint8
	reserved [512 - 144]uint8
}

/**
type msg_report_resp struct {
	status      uint32
	report_size uint32
	reserved    [0x20 - 0x8]uint8
	report      attestation_report
}
*/
