/*
 * Copyright (C) 2018 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 */

#ifndef FIO_ZBD_H
#define FIO_ZBD_H

#include "io_u.h"
#include "ioengines.h"
#include "oslib/blkzoned.h"
#include "zbd_types.h"

#ifndef RWF_ZONE_APPEND
#define RWF_ZONE_APPEND        0x00000020
#endif

struct fio_file;

enum io_u_action {
	io_u_accept	= 0,
	io_u_eof	= 1,
};
enum zone_last_io_status {
	ZONE_LAST_IO_NOT_SUBMITTED	= 0,
	ZONE_LAST_IO_QUEUED		= 1,
	ZONE_LAST_IO_COMPLETED		= 2,
};

/**
 * struct fio_zone_info - information about a single ZBD zone
 * @start: zone start location (bytes)
 * @wp: zone write pointer location (bytes)
 * @pending_ios: Number of IO's pending in this zone
 * @capacity: maximum writable location within a zone (bytes)
 * @verify_block: number of blocks that have been verified for this zone
 * @mutex: protects the modifiable members in this structure
 * @reset_cond: zone reset check condition. only relevant for zone_append.
 * @type: zone type (BLK_ZONE_TYPE_*)
 * @cond: zone state (BLK_ZONE_COND_*)
 * @open: whether or not this zone is currently open. Only relevant if
 *		max_open_zones > 0.
 * @reset_zone: whether or not this zone should be reset before writing to it
 */
struct fio_zone_info {
	pthread_mutex_t		mutex;
	pthread_cond_t		reset_cond;
	uint64_t		start;
	uint64_t		wp;
	uint64_t		dev_wp;
	uint64_t		capacity;
	uint32_t		verify_block;
	uint32_t		ow_count;
	uint32_t		pending_ios;
	uint64_t		prev_ow_lba;
	uint8_t			finish_pct;
	enum zbd_zone_type	type:2;
	enum zbd_zone_cond	cond:4;
	unsigned int		open:1;
	unsigned int		reset_zone:1;
	unsigned int		finish_zone:1;
	unsigned int		io_q_count;
	uint8_t			last_io;
	uint64_t		*zone_io_q;
};

/**
 * zoned_block_device_info - zoned block device characteristics
 * @model: Device model.
 * @max_open_zones: global limit on the number of simultaneously opened
 *	sequential write zones.
 * @mutex: Protects the modifiable members in this structure (refcount and
 *		num_open_zones).
 * @zone_size: size of a single zone in bytes.
 * @sectors_with_data: total size of data in all zones in units of 512 bytes
 * @zone_size_log2: log2 of the zone size in bytes if it is a power of 2 or 0
 *		if the zone size is not a power of 2.
 * @nr_zones: number of zones
 * @refcount: number of fio files that share this structure
 * @num_open_zones: number of open zones
 * @write_cnt: Number of writes since the latest zone reset triggered by
 *	       the zone_reset_frequency fio job parameter.
 * @open_zones: zone numbers of open zones
 * @zone_info: description of the individual zones
 *
 * Only devices for which all zones have the same size are supported.
 * Note: if the capacity is not a multiple of the zone size then the last zone
 * will be smaller than 'zone_size'.
 */
struct zoned_block_device_info {
	enum zbd_zoned_model	model;
	uint32_t		max_open_zones;
	pthread_mutex_t		mutex;
	uint64_t		zone_size;
	uint64_t		sectors_with_data;
	uint32_t		zone_size_log2;
	uint32_t		nr_zones;
	uint32_t		refcount;
	uint32_t		write_cnt;
	uint64_t		*zones_io_q_buf;
	struct fio_zone_info	zone_info[0];
};

#define NVME_IOCTL_ADMIN_CMD	_IOWR('N', 0x41, struct nvme_admin_cmd)

int zbd_setup_files(struct thread_data *td);
void zbd_free_zone_info(struct fio_file *f);
void zbd_file_reset(struct thread_data *td, struct fio_file *f);
bool zbd_unaligned_write(int error_code);
void setup_zbd_zone_mode(struct thread_data *td, struct io_u *io_u);
enum fio_ddir zbd_adjust_ddir(struct thread_data *td, struct io_u *io_u,
							enum fio_ddir ddir);
enum io_u_action zbd_adjust_block(struct thread_data *td, struct io_u *io_u);
char *zbd_write_status(const struct thread_stat *ts);
unsigned int zbd_can_zrwa_queue_more(struct thread_data *td,
				const struct io_u *io_u);

static inline void zbd_close_file(struct fio_file *f)
{
	if (f->zbd_info)
		zbd_free_zone_info(f);
}

static inline void zbd_queue_io_u(struct thread_data *td,
		struct io_u *io_u, enum fio_q_status status)
{
	if (io_u->zbd_queue_io) {
		io_u->zbd_queue_io(td, io_u, status, io_u->error == 0);
		io_u->zbd_queue_io = NULL;
	}
}

static inline void zbd_put_io_u(struct thread_data *td,
					struct io_u *io_u)
{
	if (io_u->zbd_put_io) {
		io_u->zbd_put_io(td, io_u);
		io_u->zbd_queue_io = NULL;
		io_u->zbd_put_io = NULL;
	}
}

#endif /* FIO_ZBD_H */
