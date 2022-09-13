package main

// Token is the container for the decoded token in SEV-SNP environment
type Token struct {
	tcb_version        struct{}
	signature          struct{}
	attestation_report struct{}
	msg_report_resp    struct{}
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
	guest             uint32
	policy            uint64
	family_id         [16]uint8
	image_id          [16]uint8
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

type msg_report_resp struct {
	status      uint32
	report_size uint32
	reserved    [0x20 - 0x8]uint8
	report      attestation_report
}
