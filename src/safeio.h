// safeio.h

#ifndef safeio_H
#define safeio_H

#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <unistd.h>

#ifndef SSIZE_MAX
#define SSIZE_MAX (SIZE_MAX / 2 - 1)
#endif

ssize_t safe_write(const int fd, const void* const buf_, size_t count,
	const int timeout);

ssize_t safe_read(const int fd, void* const buf_, size_t count);

ssize_t safe_read_partial(const int fd, void* const buf_,
	const size_t max_count);

#endif
