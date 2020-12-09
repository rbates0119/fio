/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 */
#ifndef FIO_BLKZONED_H
#define FIO_BLKZONED_H

#include "zbd_types.h"

#ifdef CONFIG_HAS_BLKZONED
extern int blkzoned_get_zoned_model(struct thread_data *td,
			struct fio_file *f, enum zbd_zoned_model *model);
extern int blkzoned_report_zones(struct thread_data *td,
				struct fio_file *f, uint64_t offset,
				struct zbd_zone *zones, unsigned int nr_zones);
extern int zbd_zone_mgmt_report(struct thread_data *td, struct fio_file *f,
		  uint64_t offset, struct zbd_zone *zones,
		  unsigned int nr_zones, uint16_t block_size);
extern int blkzoned_reset_wp(struct thread_data *td, const struct fio_file *f,
				uint64_t offset, uint64_t length);
extern char *read_file(const char *path);
extern int zbd_get_open_count(int fd, int nsid, int implicit);
extern bool zbd_identify_ns(struct thread_data *td,
		struct fio_file *f, void *ns, void *ns_zns, int nsid);
extern int zbd_get_nsid(struct fio_file *f);
extern bool zbd_zone_reset(struct thread_data *td,
		struct fio_file *f, uint64_t llba, bool all_zones, int nsid);
extern int zbd_issue_finish(struct thread_data *td, struct fio_file *f,
		      uint64_t offset, uint64_t length);
extern bool zbd_issue_commit_zone(const struct fio_file *f, uint32_t zone_idx,
			uint64_t lba, uint64_t slba, int nsid);
extern bool zbd_issue_exp_open_zrwa(const struct fio_file *f, uint32_t zone_idx,
			uint64_t slba , uint32_t nsid);

#else
/*
 * Define stubs for systems that do not have zoned block device support.
 */
static inline int blkzoned_get_zoned_model(struct thread_data *td,
			struct fio_file *f, enum zbd_zoned_model *model)
{
	/*
	 * If this is a block device file, allow zbd emulation.
	 */
	if (f->filetype == FIO_TYPE_BLOCK) {
		*model = ZBD_NONE;
		return 0;
	}

	return -ENODEV;
}
static inline int blkzoned_report_zones(struct thread_data *td,
				struct fio_file *f, uint64_t offset,
				struct zbd_zone *zones, unsigned int nr_zones)
{
	return -EIO;
}
static int zbd_zone_mgmt_report(struct thread_data *td, struct fio_file *f,
		  uint64_t offset, struct zbd_zone *zones,
		  unsigned int nr_zones, uint16_t block_size);
{
	return -EIO;
}
static inline int blkzoned_reset_wp(struct thread_data *td, const struct fio_file *f,
				    uint64_t offset, uint64_t length)
{
	return -EIO;
}

static inline int zbd_get_open_count(int fd, int nsid, int implicit)
{
	return -EIO;
}
static inline char *read_file(const char *path)
{
	return -EIO;
}
static inline bool zbd_identify_ns(struct thread_data *td,
		struct fio_file *f, void *ns, void *ns_zns, int nsid)
{
	return false;
}

static inline int zbd_get_nsid(struct fio_file *f)
{
	return -EIO;
}

static inline bool zbd_zone_reset(struct thread_data *td, struct fio_file *f,
		uint64_t llba, bool all_zones, int nsid)
{
	return -EIO;
}

static inline int zbd_issue_finish(struct thread_data *td, struct fio_file *f,
		      uint64_t offset, uint64_t length)
{
	return -EIO;
}
static inline bool zbd_issue_commit_zone(const struct fio_file *f, uint32_t zone_idx,
		uint64_t lba, uint64_t slba, int nsid)
{
	return false;
}

static inline bool zbd_issue_exp_open_zrwa(const struct fio_file *f, uint32_t zone_idx,
		uint64_t slba , uint32_t nsid)
{
	return false;
}

#endif

#endif /* FIO_BLKZONED_H */
