#ifndef __SERIALIZE__
#define __SERIALIZE__

#include <stdlib.h>
#include <sqlite3.h>
#include "filerec.h"

#define DB_VERSION	"1"

struct db_header {
	uint64_t	num_files;
	uint64_t	num_hashes;
	uint32_t	block_size;
};

/* IMPORTANT: you should not use that without mutex */
sqlite3 *db;

int init_db(char *filename);
int create_index(void);
int write_file_info(struct filerec *file);
int write_one_hash(uint64_t loff, uint32_t flags, unsigned char *digest);
int read_hash_tree(char *filename, struct hash_tree *tree,
                   unsigned int *block_size, struct db_header *ret_hdr,
		   int ignore_hash_type, struct rb_root *scan_tree);
void db_begin_transac(void);
void db_commit(void);
int write_header(uint32_t block_size);
#endif /* __SERIALIZE__ */
