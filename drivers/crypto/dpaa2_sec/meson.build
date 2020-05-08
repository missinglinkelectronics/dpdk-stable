# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2018 NXP

version = 2

if host_machine.system() != 'linux'
        build = false
endif

deps += ['security', 'mempool_dpaa2']
sources = files('dpaa2_sec_dpseci.c',
		'mc/dpseci.c')

# FIXME: temporary solution for Bugzilla 469
if (toolchain == 'gcc' and cc.version().version_compare('>=10.0.0'))
	cflags += '-fcommon'
endif

allow_experimental_apis = true

includes += include_directories('mc', 'hw')
