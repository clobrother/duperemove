/*
 * serialize.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>

#include "hash-tree.h"
#include "serialize.h"
#include "debug.h"
#include "bloom.h"
#include "d_tree.h"

#define FILENAME "/home/jack/test.db"

sqlite3_stmt *ins_hash_stmt = NULL;
sqlite3_stmt *ins_file_stmt = NULL;
sqlite3_stmt *sel_hash_stmt = NULL;
sqlite3_stmt *sel_file_stmt = NULL;

sqlite3_int64 last_inserted = 0;

struct bloom bloom;

static int exec_query(char *sql)
{
	int ret;
	char *err;

	ret = sqlite3_exec(db, sql, NULL, NULL, &err);
	if (ret != SQLITE_OK) {
		printf("exec_query: %s\n", err);
		sqlite3_free(err);
		return -1;
	}
	dprintf("query executed successfully: %s\n", sql);
	return 0;
}

static int open_db(char *filename)
{
	int ret;
	ret = sqlite3_open(filename, &db);
	if (ret) {
		fprintf(stderr, "sqlite3_open: %s\n", sqlite3_errmsg(db));
		return -1;
	}
	return 0;
}

/*
 * Make the db faster (& risky), for initial insertions.
 * TODO: for sane updates, switch off these for a safer state
 */
static void burst_db(void)
{
	exec_query("PRAGMA synchronous = OFF");
	exec_query("PRAGMA journal_mode = MEMORY");
}

static void create_tables(void)
{
	char *sql;
	sql = "create table if not exists file_info (\
		id integer primary key,\
		inum int,\
		subvolid int,\
		num_blocks int,\
		filename text);";
	exec_query(sql);

	sql = "create table if not exists hashes (\
		file_id int,\
		digest text,\
		flags int,\
		loff int);";
	exec_query(sql);

	sql = "create table if not exists config (\
		key text,\
		value int);";
	exec_query(sql);
}

static void free_stmt(void)
{
	sqlite3_finalize(ins_hash_stmt);
	sqlite3_finalize(ins_file_stmt);
	sqlite3_finalize(sel_hash_stmt);
	sqlite3_finalize(sel_file_stmt);
}

static int compile_stmt(void)
{
	int ret;

	char *ins_file_sql = "insert into file_info (\
			      id, inum, subvolid, num_blocks, filename)\
			      values(NULL, ?, ?, ?, ?);";

	char *ins_hash_sql = "insert into hashes (\
			      file_id, digest, flags, loff)\
			      values(?, ?, ?, ?);";

	char *sel_hash_sql = "select digest, flags, loff\
			      from hashes where file_id = ?";
	char *sel_file_sql = "select id, inum, subvolid, num_blocks, filename\
			      from file_info";

	ret = sqlite3_prepare_v2(db, ins_hash_sql, -1, &ins_hash_stmt, NULL);
	ret |= sqlite3_prepare_v2(db, ins_file_sql, -1, &ins_file_stmt, NULL);
	ret |= sqlite3_prepare_v2(db, sel_hash_sql, -1, &sel_hash_stmt, NULL);
	ret |= sqlite3_prepare_v2(db, sel_file_sql, -1, &sel_file_stmt, NULL);
	if (ret == SQLITE_OK)
		return 0;

	fprintf(stderr, "stmt compilation failed: %s\n", sqlite3_errstr(ret));
	free_stmt();
	return -1;
}

void db_begin_transac(void)
{
	char *sql = "begin transaction";
	exec_query(sql);
}

void db_commit(void)
{
	char *sql = "end transaction";
	exec_query(sql);
}

static void close_db(void)
{
	free_stmt();
	sqlite3_close(db);
}

int init_db(void)
{
	open_db(FILENAME);

	burst_db();
	create_tables();
	compile_stmt();

	atexit(close_db);
	return 0;
}

int write_file_info(struct filerec *file)
{
	int ret, result = 0;

	ret = sqlite3_bind_int64(ins_file_stmt, 1, (sqlite3_int64)file->inum);
	ret |= sqlite3_bind_int64(ins_file_stmt, 2, (sqlite3_int64)0);
	ret |= sqlite3_bind_int64(ins_file_stmt, 3, (sqlite3_int64)file->num_blocks);
	ret |= sqlite3_bind_text(ins_file_stmt, 4, file->filename,
				 strlen(file->filename), SQLITE_TRANSIENT);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "bind failed: %s\n", sqlite3_errstr(ret));
		result = -1;
		goto out;
	}

	ret = sqlite3_step(ins_file_stmt);
	if (ret != SQLITE_DONE) {
		fprintf(stderr, "step failed: %s\n", sqlite3_errstr(ret));
		result = -1;
		goto out;
	}

	last_inserted = sqlite3_last_insert_rowid(db);

out:
	sqlite3_reset(ins_file_stmt);
	return result;
}


int write_one_hash(uint64_t loff, uint32_t flags, unsigned char *digest)
{
	int ret;

	ret = sqlite3_bind_int64(ins_hash_stmt, 1, last_inserted);
	ret |= sqlite3_bind_text(ins_hash_stmt, 2, (char*)digest,
				 DIGEST_LEN_MAX, SQLITE_TRANSIENT);
	ret |= sqlite3_bind_int64(ins_hash_stmt, 3, (sqlite3_int64)flags);
	ret |= sqlite3_bind_int64(ins_hash_stmt, 4, (sqlite3_int64)loff);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "bind failed: %s\n", sqlite3_errstr(ret));
		ret = -1;
		goto out;
	}

	if (sqlite3_step(ins_hash_stmt) != SQLITE_DONE) {
		fprintf(stderr, "step failed: %s\n", sqlite3_errstr(ret));
		ret = -1;
		goto out;
	}
	ret = 0;

out:
	sqlite3_reset(ins_hash_stmt);
	return ret;
}

static int select_file(uint64_t *id, uint64_t *inum, uint64_t *subvolid,
		       const unsigned char **filename)
{
	int ret, result = 1;

	ret = sqlite3_step(sel_file_stmt);
	if (ret == SQLITE_DONE) {
		result = 0;
		goto reset;
	}

	if (ret != SQLITE_ROW) {
		fprintf(stderr, "select_file: %s\n", sqlite3_errstr(ret));
		result = -1;
		goto reset;
	}

	*id = (uint64_t)sqlite3_column_int64(sel_file_stmt, 0);
	*inum = (uint64_t)sqlite3_column_int64(sel_file_stmt, 1);
	*subvolid = (uint64_t)sqlite3_column_int64(sel_file_stmt, 2);
	*filename = sqlite3_column_text(sel_file_stmt, 4);
	goto out;

reset:
	sqlite3_reset(sel_file_stmt);
out:
	return result;
}

static int select_hash(uint64_t fileid, const unsigned char **digest,
		       uint32_t *flags, uint64_t *loff)
{
	int ret, result = 1;

	ret = sqlite3_step(sel_hash_stmt);
	if (ret == SQLITE_DONE) {
		result = 0;
		goto reset;
	}

	if (ret != SQLITE_ROW) {
		fprintf(stderr, "select_hash: %s\n", sqlite3_errstr(ret));
		result = -1;
		goto reset;
	}

	*digest = sqlite3_column_text(sel_hash_stmt, 0);
	*flags = (uint32_t)sqlite3_column_int64(sel_hash_stmt, 1);
	*loff = (uint64_t)sqlite3_column_int64(sel_hash_stmt, 2);
	goto out;

reset:
	sqlite3_reset(sel_hash_stmt);
out:
	return result;
}

static int read_one_file(struct hash_tree *tree, struct rb_root *scan_tree,
			 struct filerec *file, uint64_t id)
{
	int ret;
	uint32_t flags;
	uint64_t loff;
	const unsigned char *digest;
	int result = 0;

	dprintf("Reading hashes with fileid = %"PRIu64"\n", id);
        ret = sqlite3_bind_int64(sel_hash_stmt, 1, (sqlite3_int64)id);
        if (ret != SQLITE_OK) {
                fprintf(stderr, "failed to bind fileid: %s\n", sqlite3_errstr(ret));
		result = -1;
		goto out;
        }

	while(true) {
		ret = select_hash(id, &digest, &flags, &loff);
		if (ret == -1) {
			result = -1;
			goto out;
		}

		if (ret == 0)
			goto out;

		if (ret == 1) {
			if (!tree) { /* First pass */
				ret = bloom_add(&bloom, digest, DIGEST_LEN_MAX);
				if (ret == 1) {
					ret = digest_insert(scan_tree, digest);
					if (ret)
						return ret;
				}
				continue;
			}

			/* 2nd pass */
			if (scan_tree && !digest_find(scan_tree, digest))
				continue;

			ret = insert_hashed_block(tree, digest, file, loff, flags);
			if (ret) {
				result = ENOMEM;
				goto out;
			}
		}
	}

out:
	sqlite3_reset(sel_hash_stmt);
	return result;
}

static int read_header(struct db_header *h)
{
	char *sql;
	sqlite3_stmt *stmt;
	int ret;
	const unsigned char *version;

	sql = "select value from config where key = ?";
	ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	ret |= sqlite3_bind_text(stmt, 1, "version", 7, 0);
	ret |= sqlite3_step(stmt);
	if (ret != (SQLITE_OK | SQLITE_ROW))
		goto out;

	version = sqlite3_column_text(stmt, 0);
	if (strcmp((char *)version, DB_VERSION) != 0) {
		fprintf(stderr, "Version mismatch (found %s, I have %s)\n", 
				version, DB_VERSION);
		goto clean;
	}

	sqlite3_reset(stmt);
	ret = sqlite3_bind_text(stmt, 1, "blocksize", 9, 0);
	ret |= sqlite3_step(stmt);
	if (ret != (SQLITE_OK | SQLITE_ROW))
		goto out;

	h->block_size = (uint32_t)sqlite3_column_int64(stmt, 0);
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	sql = "select count(*) from file_info";
	ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	ret |= sqlite3_step(stmt);
	if (ret != (SQLITE_OK | SQLITE_ROW))
		goto out;
	
	h->num_files = (uint64_t)sqlite3_column_int64(stmt, 0);
	sqlite3_finalize(stmt);

	sql = "select count(*) from hashes";
	ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	ret |= sqlite3_step(stmt);
	if (ret != (SQLITE_OK | SQLITE_ROW))
		goto out;
	
	h->num_hashes = (uint64_t)sqlite3_column_int64(stmt, 0);
	sqlite3_finalize(stmt);
	return 0;

out:
	/* data missing or error. Successful select returns SQLITE_ROW */
	if (ret == SQLITE_DONE)
		fprintf(stderr, "read_header: data not found\n");
	else
		fprintf(stderr, "read_header: %s (%i)\n", sqlite3_errstr(ret), ret);
clean:
	sqlite3_finalize(stmt);
	return -1;
}


int read_hash_tree(char *filename, struct hash_tree *tree,
                   unsigned int *block_size, struct db_header *ret_hdr,
		   int ignore_hash_type, struct rb_root *scan_tree)
{
	int ret;
	uint64_t id, inum, subvolid;
	const unsigned char *file_path;
	struct filerec *file;
	int result = 0;
	struct db_header h;

	ret = read_header(&h);
	if (ret)
		return -1;

	if (ret_hdr)
		memcpy(ret_hdr, &h, sizeof(struct db_header));

	if (tree == NULL && scan_tree != NULL) {
		ret = bloom_init(&bloom, h.num_hashes, 0.01);
		if (ret)
			goto out;
		printf("Bloom init completed\n");
	}

	while(true) {
		ret = select_file(&id, &inum, &subvolid, &file_path);
		if (ret == -1) {
			result = -1;
			goto out;
		}

		if (ret == 0)
			goto out;

		if (ret == 1) {
			dprintf("%"PRIu64", %"PRIu64", %"PRIu64", %s\n", id, inum, subvolid, file_path);
			file = filerec_new((char *)file_path, inum, subvolid);
			read_one_file(tree, scan_tree, file, id);
		}
	}

out:
	sqlite3_reset(sel_file_stmt);
	return result;
}

int write_header(uint32_t block_size)
{
	char *sql;
	sqlite3_stmt *stmt;
	int ret;

	sql = "insert into config(key, value) values(?, ?)";
	ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (ret != SQLITE_OK)
		goto err;

	ret = sqlite3_bind_text(stmt, 1, "version", 7, 0);
	ret |= sqlite3_bind_text(stmt, 2, DB_VERSION, strlen(DB_VERSION), 0);
	ret |= sqlite3_step(stmt);

	if (ret != (SQLITE_OK | SQLITE_DONE))
		goto err;

	sqlite3_reset(stmt);

	ret = sqlite3_bind_text(stmt, 1, "blocksize", 9, 0);
	ret |= sqlite3_bind_int64(stmt, 2, (sqlite3_int64)block_size);
	ret |= sqlite3_step(stmt);

	if (ret != (SQLITE_OK | SQLITE_DONE))
		goto err;

	sqlite3_finalize(stmt);
	return 0;

err:
	fprintf(stderr, "write_header: %s\n", sqlite3_errstr(ret));
	sqlite3_finalize(stmt);
	return -1;
}
