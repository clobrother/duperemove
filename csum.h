#ifndef __CSUM_H__
#define __CSUM_H__

#include <stdio.h>

#define	DIGEST_LEN_MAX	32
#define DEFAULT_HASH_STR	"murmur3"

extern unsigned int digest_len;
extern char hash_type[8];

/* Init / debug */
int init_csum_module(const char *type);
void debug_print_digest(FILE *stream, unsigned char *digest);

/* Checksums a single block in one go. */
void checksum_block(const char *buf, int len, unsigned char *digest);

/* Keeping a 'running' checksum - we add data to it a bit at a time */
struct running_checksum;
struct running_checksum *start_running_checksum(void);
void add_to_running_checksum(struct running_checksum *c,
			     unsigned int len, unsigned char *buf);
void finish_running_checksum(struct running_checksum *c, unsigned char *digest);

/* csum-module implementation details */

struct csum_module_ops {
	int (*init)(unsigned int *ret_digest_len);
	void (*checksum_block)(const char *buf, int len, unsigned char *digest);
	struct running_checksum *(*start_running_checksum)(void);
	void (*add_to_running_checksum)(struct running_checksum *c,
					unsigned int len, unsigned char *buf);
	void (*finish_running_checksum)(struct running_checksum *c,
					unsigned char *digest);
};

struct csum_module {
	/*
	 * Friendly name, suitable for printing to the user. We use
	 * this also for option parsing.
	 */
	const char *name;

	/*
	 * Internally identifies this hash, is also what we write in
	 * hashfiles. Must not exceed 8 characters.
	 */
	const char *hash_type;
	struct csum_module_ops *ops;
};

extern struct csum_module csum_module_sha256;
extern struct csum_module csum_module_xxhash;
extern struct csum_module csum_module_murmur3;

extern struct csum_module *csum_mod; /* The module currently in use */

#define	DECLARE_RUNNING_CSUM_CAST_FUNCS(_type)				\
static inline struct _type *						\
rc_to_priv(struct running_checksum *rc)					\
{									\
	return (struct _type *)rc;					\
}									\
static inline struct running_checksum *					\
priv_to_rc(struct _type *priv)						\
{									\
	return (struct running_checksum *)priv;				\
}

#endif	/* csum.h */
