// encp.c

#include "encp.h"

int quiet = 0;

static void usage(void){
	puts("encp - Simple data en/decryption\nEncrypt (default) or decrypt stdin "
		"or file to stdout with keyfile or password.\nUsage:  encp [-d|--decrypt] "
		"[<file>] [<options>]\n    Options:  [-q|--quiet] [-r|--random | "
		"-k|--keyfile] | -h|--help\n        -r|--random:             Encrypt "
		"with random password (and display it)\n        -k|--keyfile <keyfile>:  "
		"Use (part of) <keyfile> as the password\n        "
		"-q|--quiet:              Suppress output on stderr (errors and "
		"prompts)\n        -h|--help:               Show this help text (ignore "
		"all other options)\n    A password must be entered if -r|--random and "
		"-k|--keyfile are not given.");
	exit(0);
}

static void die(int print_errno, const char *format, ...){
	if (!quiet){
		va_list ap;
		va_start(ap, format);
		fprintf(stderr, "Abort: ");
		vfprintf(stderr, format, ap);
		va_end(ap);
		if (print_errno) fprintf(stderr, " - %s", strerror(errno));
		fprintf(stderr, "\n");
	}
  exit(1);
}

static int read_file(const char *file){
	if (file == NULL) return 0;
	int fd = open(file, O_RDONLY);
	if (fd == -1) die(1, "unable to read '%s'", file);
	return fd;
}

static void derive_key(Context *ctx, char *password, size_t password_len){
	static uint8_t master_key[hydro_pwhash_MASTERKEYBYTES] = {0};
	if (hydro_pwhash_deterministic(ctx->key, sizeof ctx->key, password,
			password_len, HYDRO_CONTEXT, master_key, PWHASH_OPSLIMIT,
			PWHASH_MEMLIMIT, PWHASH_THREADS) != 0) die(0, "password hashing failed");
	hydro_memzero(password, password_len);
}

static int stream_encrypt(Context *ctx){
	unsigned char *const chunk_size_p = ctx->buf;
	unsigned char *const chunk = chunk_size_p + 4;
	uint64_t chunk_id;
	ssize_t chunk_size;
	chunk_id = 0;
	while ((chunk_size = safe_read_partial(ctx->fd_in, chunk, MAX_CHUNK_SIZE))
			>= 0){
		STORE32_LE(chunk_size_p, (uint32_t) chunk_size);
		if (hydro_secretbox_encrypt(chunk, chunk, chunk_size, chunk_id,
				HYDRO_CONTEXT, ctx->key) != 0) die(0, "encryption error");
		if (write(1, chunk_size_p, 4 + hydro_secretbox_HEADERBYTES + chunk_size) <
				0) die(1, "write()");
		if (chunk_size == 0) break;
		chunk_id++;
	}
	if (chunk_size < 0) die(1, "read()");
	return 0;
}

static int stream_decrypt(Context *ctx){
	unsigned char *const chunk_size_p = ctx->buf;
	unsigned char *const chunk = chunk_size_p + 4;
	uint64_t chunk_id;
	ssize_t readnb, chunk_size = MAX_CHUNK_SIZE;
	chunk_id = 0;
	while ((readnb = safe_read(ctx->fd_in, chunk_size_p, 4)) == 4){
		chunk_size = LOAD32_LE(chunk_size_p);
		if (chunk_size > MAX_CHUNK_SIZE)
			die(0, "chunk size too large (%zd > %zd)", chunk_size, MAX_CHUNK_SIZE);
		if (safe_read(ctx->fd_in, chunk, chunk_size + hydro_secretbox_HEADERBYTES)
				!= chunk_size + hydro_secretbox_HEADERBYTES)
			die(0, "chunk too short (%zd bytes expected)", chunk_size);
		if (hydro_secretbox_decrypt(chunk, chunk, chunk_size +
				hydro_secretbox_HEADERBYTES, chunk_id, HYDRO_CONTEXT, ctx->key) != 0 &&
				!quiet){
			fprintf(stderr, "Unable to decrypt chunk #%" PRIu64 " - ", chunk_id);
			if (chunk_id == 0) die(0, "wrong password or key?");
			else die(0, "corrupted or incomplete file?");
		}
		if (chunk_size == 0) break;
		if (write(1, chunk, chunk_size) < 0) die(1, "write()");
		chunk_id++;
	}
	if (readnb < 0) die(1, "read()");
	if (chunk_size != 0) die(0, "premature end of file");
	return 0;
}

static int read_keyfile(Context *ctx, const char *file){
	char password_[KEYLENGTH], *password = password_;
	ssize_t password_len;
	int fd = read_file(file);
	if ((password_len = safe_read(fd, password, sizeof password_)) < 0)
		die(1, "unable to read the keyfile");
	while (password_len > 0 && (password[password_len - 1] == ' ' ||
			password[password_len - 1] == '\r' ||
			password[password_len - 1] == '\n')) password_len--;
	while (password_len > 0 && (*password == ' ' || *password == '\r' ||
			*password == '\n')){
		password++;
		password_len--;
	}
	if (password_len <= 0) die(0, "empty password");
	close(fd);
	derive_key(ctx, password, password_len);
	return 0;
}

static void passgen(Context *ctx){
	unsigned char pw[PASSWORD_BYTES];
	char password[PASSWORD_LENGTH + 1];
	hydro_random_buf(pw, PASSWORD_BYTES);
	hydro_bin2hex(password, PASSWORD_LENGTH + 1, pw, PASSWORD_BYTES);
	if (!quiet) fprintf(stderr, "Password: ");
	fprintf(stderr, "%s\n", password);
	derive_key(ctx, password, PASSWORD_LENGTH);
	hydro_memzero(pw, PASSWORD_BYTES);
	hydro_memzero(password, PASSWORD_LENGTH);
}

static void options_parse(Context *ctx, int argc, char *argv[]){
	static const char *optstring = "hqdk:r";
	static struct option longopts[] = {
		{"help", 0, NULL, 'h'},
		{"quiet", 0, NULL, 'q'},
		{"decrypt", 0, NULL, 'd'},
		{"keyfile", 1 ,NULL, 'k' },
		{"random", 0, NULL, 'r'},
		{NULL, 0, NULL, 0}
	};

	int optflag, longindex = 0, random = 0;
	char* keyfile = NULL;
	ctx->encrypt = 1;
	ctx->in = NULL;
	optind = 0, opterr = 0;
	while ((optflag = getopt_long(argc, argv, optstring,
			longopts, &longindex)) != -1){
		switch (optflag){
			case 'h': usage(); break;
			case 'q': quiet = 1; break;
			case 'd': ctx->encrypt = 0; break;
			case 'k': keyfile = optarg; break;
			case 'r': random = 1; break;
			default: die(0, "unknown flag: -%c", optopt);
		}
	}
	// Find inputfile
	if (argv[optind] != NULL){
		ctx->in = argv[optind];
		if (argv[++optind] != NULL)
			die(0, "only 1 input file can be processed");
	}
	if (random)
		if (ctx->encrypt == 0)
			die(0, "when decrypting, -r|--random is meaningless");
		else if (keyfile)
			die(0, "when using a keyfile, -r|--random is superfluous");
		else passgen(ctx);
	else if (keyfile) read_keyfile(ctx, keyfile);
	else { // Get password from stdin
		if (!quiet) fprintf(stderr, "Password? ");
		char *buf = getpass("");
		int len = strlen(buf);
		if (len == -1)
			die(0, "error reading needed password");
		if (len == 0)
			die(0, "password can't be empty");
		derive_key(ctx, buf, len);
	}
}

int main(int argc, char *argv[]){
	assert(BUFFER_SIZE >= MIN_BUFFER_SIZE);
	assert(BUFFER_SIZE <= MAX_BUFFER_SIZE);
	assert(BUFFER_SIZE >= 4 + hydro_secretbox_HEADERBYTES);
	assert(MAX_CHUNK_SIZE == BUFFER_SIZE - 4 - hydro_secretbox_HEADERBYTES);
	Context ctx;
	if (hydro_init() < 0) die(1, "unable to initialize the crypto library");
	memset(&ctx, 0, sizeof ctx);
	options_parse(&ctx, argc, argv);
	if ((ctx.buf = (unsigned char *) malloc(BUFFER_SIZE)) == NULL)
		die(1, "failed to allocate %d bytes of memory", BUFFER_SIZE);
	assert(sizeof HYDRO_CONTEXT == hydro_secretbox_CONTEXTBYTES);
	ctx.fd_in = read_file(ctx.in);
	if (ctx.encrypt) stream_encrypt(&ctx);
	else stream_decrypt(&ctx);
	free(ctx.buf);
	close(ctx.fd_in);
	close(1);
	hydro_memzero(&ctx, sizeof ctx);
	return 0;
}
