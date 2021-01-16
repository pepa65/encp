// safeio.c

#include "safeio.h"

ssize_t safe_read(const int fd, void *const buf_, size_t count){
	unsigned char *buf = (unsigned char *) buf_;
	ssize_t readnb;
	assert(count <= SSIZE_MAX);
	do {
		while ((readnb = read(fd, buf, count)) < (ssize_t) 0 && errno == EINTR);
		if (readnb < (ssize_t) 0) return readnb;
		if (readnb == (ssize_t) 0) break;
		count -= (size_t) readnb;
		buf += readnb;
	} while (count > (ssize_t) 0);
	return (ssize_t)(buf - (unsigned char *) buf_);
}

ssize_t safe_read_partial(const int fd, void *const buf_,
		const size_t max_count){
	unsigned char *const buf = (unsigned char *) buf_;
	ssize_t readnb;
	assert(max_count <= SSIZE_MAX);
	while ((readnb = read(fd, buf, max_count)) < (ssize_t) 0 && errno == EINTR);
	return readnb;
}
