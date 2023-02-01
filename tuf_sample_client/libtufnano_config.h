/*
 * Copyright 2022 Foundries.io
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __LIBTUFNANO_CONFIG_H__
#define __LIBTUFNANO_CONFIG_H__

void log_tuf_client(const char *fmt, ...);
#define log_debug(X) log_tuf_client X
#define log_info(X) log_tuf_client X
#define log_error(X) log_tuf_client X

#define TUF_SIGNATURES_PER_ROLE_MAX_COUNT 2
#define TUF_ENABLE_ED25519

#endif
