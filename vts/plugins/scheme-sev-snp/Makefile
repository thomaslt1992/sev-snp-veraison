# Copyright 2021 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

PLUGIN := ../bin/scheme-sev-snp
GOPKG := github.com/veraison/services/vts/plugins/scheme-sev-snp
SRCS := main.go

test-hook-pre:
	$(MAKE) -C test/

SUBDIR := test

include ../../../mk/common.mk
include ../../../mk/plugin.mk
include ../../../mk/lint.mk
include ../../../mk/test.mk
include ../../../mk/subdir.mk
