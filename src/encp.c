// encp.c

#include "encp.h"

static void usage(void){
	puts("encp - Simple data en/decryption\nEncrypting (default) or decrypting "
		"data with a keyfile or password.\nUsage:\n  encp [-d|--decrypt] [<in> |"
		" -o|--output <out>] [<options>] [<keyoptions>]\n    "
		"<in>,<out>:                  Files / '-' (read from stdin, write to "
		"stdout)\n    <options>:\n        -f|--force:              Allow output "
		"of encrypt to stdout\n        -h|--help:               Show this help "
		"text\n    <keyoptions>:\n        -r|--random:             Encrypt with a "
		"random password and display it\n        -k|--keyfile <keyfile>:  Use "
		"<keyfile> as the password\n  When no <keyoptions> are given, a password "
		"is asked for on stdin, in which\n  case <in> needs to be a file.\n  When "
		"encrypting, and <out> is not a file, and the output is not being "
		"piped,\n  and the -f|--forced flag is not used, then the output goes to "
		"a file named\n  'file-XXXXXXXX.encp' (XXXXXXXX is a random 4-byte "
		"hexadecimal).");
	exit(0);
}

static int file_open(const char *file, int stdio){
	int fd;
	if (file == NULL || (file[0] == '-' && file[1] == 0))
		return stdio ? STDOUT_FILENO : STDIN_FILENO;
	fd = stdio ?
		open(file, O_CREAT | O_WRONLY | O_TRUNC, 0644) :
		open(file, O_RDONLY);
	if (fd == -1) die(1, "unable to %s '%s'", stdio ? "write to" : "read from",
			file);
	return fd;
}

static void derive_key(Context *ctx, char *password, size_t password_len){
	static uint8_t master_key[hydro_pwhash_MASTERKEYBYTES] = {0};
	if (ctx->has_key) die(0, "only need one key");
	if (hydro_pwhash_deterministic(ctx->key, sizeof ctx->key, password,
			password_len, HYDRO_CONTEXT, master_key, PWHASH_OPSLIMIT,
			PWHASH_MEMLIMIT, PWHASH_THREADS) != 0) die(0, "password hashing failed");
	hydro_memzero(password, password_len);
	ctx->has_key = 1;
}

static int stream_encrypt(Context *ctx){
	unsigned char *const chunk_size_p = ctx->buf;
	unsigned char *const chunk = chunk_size_p + 4;
	uint64_t chunk_id;
	ssize_t max_chunk_size;
	ssize_t chunk_size;
	assert(ctx->sizeof_buf >= 4 + hydro_secretbox_HEADERBYTES);
	max_chunk_size = ctx->sizeof_buf - 4 - hydro_secretbox_HEADERBYTES;
	assert(max_chunk_size <= 0x7fffffff);
	chunk_id = 0;
	while ((chunk_size = safe_read_partial(ctx->fd_in, chunk, max_chunk_size))
			>= 0){
		STORE32_LE(chunk_size_p, (uint32_t) chunk_size);
		if (hydro_secretbox_encrypt(chunk, chunk, chunk_size, chunk_id,
				HYDRO_CONTEXT, ctx->key) != 0) die(0, "encryption error");
		if (safe_write(ctx->fd_out, chunk_size_p, 4 + hydro_secretbox_HEADERBYTES
				+ chunk_size, -1) < 0) die(1, "write()");
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
	ssize_t readnb;
	ssize_t max_chunk_size;
	ssize_t chunk_size;
	assert(ctx->sizeof_buf >= 4 + hydro_secretbox_HEADERBYTES);
	max_chunk_size = ctx->sizeof_buf - 4 - hydro_secretbox_HEADERBYTES;
	assert(max_chunk_size <= 0x7fffffff);
	chunk_id = 0;
	while ((readnb = safe_read(ctx->fd_in, chunk_size_p, 4)) == 4){
		chunk_size = LOAD32_LE(chunk_size_p);
		if (chunk_size > max_chunk_size)
			die(0, "chunk size too large (%zd > %zd)", chunk_size,
				max_chunk_size);
		if (safe_read(ctx->fd_in, chunk, chunk_size + hydro_secretbox_HEADERBYTES)
				!= chunk_size + hydro_secretbox_HEADERBYTES)
			die(0, "chunk too short (%zd bytes expected)", chunk_size);
		if (hydro_secretbox_decrypt(chunk, chunk, chunk_size +
				hydro_secretbox_HEADERBYTES, chunk_id, HYDRO_CONTEXT, ctx->key) != 0){
			fprintf(stderr, "Unable to decrypt chunk #%" PRIu64 " - ", chunk_id);
			if (chunk_id == 0) die(0, "wrong password or key?");
			else die(0, "corrupted or incomplete file?");
		}
		if (chunk_size == 0) break;
		if (safe_write(ctx->fd_out, chunk, chunk_size, -1) < 0) die(1, "write()");
		chunk_id++;
	}
	if (readnb < 0) die(1, "read()");
	if (chunk_size != 0) die(0, "premature end of file");
	return 0;
}

static int read_keyfile(Context *ctx, const char *file){
	char password_[512], *password = password_;
	ssize_t password_len;
	int fd;
	fd = file_open(file, 0);
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
	fprintf(stderr, "Password: ");
	puts(password);
	derive_key(ctx, password, PASSWORD_LENGTH);
	hydro_memzero(pw, PASSWORD_BYTES);
	hydro_memzero(password, PASSWORD_LENGTH);
}

static void options_parse(Context *ctx, int argc, char *argv[]){
	static const char *optstring = "hfdo:k:r";
	static struct option longopts[] = {
		{"help", 0, NULL, 'h'},
		{"force", 0, NULL, 'f'},
		{"decrypt", 0, NULL, 'd'},
		{"output", 1, NULL, 'o'},
		{"keyfile", 1 ,NULL, 'k' },
		{"random", 0, NULL, 'r'},
		{NULL, 0, NULL, 0}
	};

	int optflag, longindex = 0, random = 0, force = 0;
	char* keyfile = NULL;
	ctx->encrypt = 1;
	ctx->in = NULL;
	ctx->out = NULL;
	optind = 0, opterr = 0;
	while ((optflag = getopt_long(argc, argv, optstring,
			longopts, &longindex)) != -1){
		switch (optflag){
			case 'h': usage(); break;
			case 'f': force = 1; break;
			case 'd': ctx->encrypt = 0; break;
			case 'o':
				if (ctx->out) die(0, "only 1 output file allowed");
				ctx->out = malloc(MIN_BUFFER_SIZE);
				strcpy(ctx->out, optarg);
				break;
			case 'k': keyfile = optarg; break;
			case 'r': random = 1; break;
			default: die(0, "unknown flag: -%c", optopt);
		}
	}
	// Handle unflagged argument(s)
	if (argv[optind] != NULL){
		ctx->in = malloc(MIN_BUFFER_SIZE);
		strcpy(ctx->in, argv[optind++]);
	}
	if (argv[optind] != NULL)
		die(0, "only 1 input file can be processed");
	if (!force && ctx->encrypt == 1 && ctx->out == NULL && isatty(1)){
		char *outfile = malloc(19);
		sprintf(outfile, "file-%08x.encp", hydro_random_u32());
		ctx->out = outfile;
	}
	if (random)
		if (ctx->encrypt == 0)
			die(0, "when decrypting, -r|--random is meaningless");
		else if (keyfile)
			die(0, "when using a keyfile, -r|--random is superfluous");
		else passgen(ctx);
	else if (keyfile) read_keyfile(ctx, keyfile);
	else if (ctx->in == NULL)
		die(0, "using stdin for data input, but also need a password");
	else { // Get password from stdin
		fprintf(stderr, "Password: ");
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
	Context ctx;
	if (hydro_init() < 0) die(1, "unable to initialize the crypto library");
	memset(&ctx, 0, sizeof ctx);
	options_parse(&ctx, argc, argv);
	ctx.sizeof_buf = DEFAULT_BUFFER_SIZE;
	if (ctx.sizeof_buf < MIN_BUFFER_SIZE) ctx.sizeof_buf = MIN_BUFFER_SIZE;
	else if (ctx.sizeof_buf > MAX_BUFFER_SIZE) ctx.sizeof_buf = MAX_BUFFER_SIZE;
	if ((ctx.buf = (unsigned char *) malloc(ctx.sizeof_buf)) == NULL)
		die(1, "malloc()");
	assert(sizeof HYDRO_CONTEXT == hydro_secretbox_CONTEXTBYTES);
	ctx.fd_in = file_open(ctx.in, 0);
	ctx.fd_out = file_open(ctx.out, 1);
	if (ctx.encrypt) stream_encrypt(&ctx);
	else stream_decrypt(&ctx);
	free(ctx.buf);
	close(ctx.fd_out);
	close(ctx.fd_in);
	hydro_memzero(&ctx, sizeof ctx);
	return 0;
}
