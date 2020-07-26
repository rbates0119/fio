/*
 * Copyright (C) 2018 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 */

#ifndef FIO_ZBD_H
#define FIO_ZBD_H

#include <inttypes.h>
#include "fio.h"	/* FIO_MAX_OPEN_ZBD_ZONES */
#ifdef CONFIG_LINUX_BLKZONED
#include <linux/blkzoned.h>
#endif

struct fio_file;

/*
 * Zoned block device models.
 */
enum blk_zoned_model {
	ZBD_DM_NONE,	/* Regular block device */
	ZBD_DM_HOST_AWARE,	/* Host-aware zoned block device */
	ZBD_DM_HOST_MANAGED,	/* Host-managed zoned block device */
};

enum io_u_action {
	io_u_accept	= 0,
	io_u_eof	= 1,
};

/**
 * struct fio_zone_info - information about a single ZBD zone
 * @start: zone start location (bytes)
 * @wp: zone write pointer location (bytes)
 * @capacity: maximum writable location within a zone (bytes)
 * @verify_block: number of blocks that have been verified for this zone
 * @mutex: protects the modifiable members in this structure
 * @type: zone type (BLK_ZONE_TYPE_*)
 * @cond: zone state (BLK_ZONE_COND_*)
 * @open: whether or not this zone is currently open. Only relevant if
 *		max_open_zones > 0.
 * @reset_zone: whether or not this zone should be reset before writing to it
 */
struct fio_zone_info {
#ifdef CONFIG_LINUX_BLKZONED
	pthread_mutex_t		mutex;
	uint64_t		start;
	uint64_t		wp;
	uint64_t		capacity;
	uint32_t		verify_block;
	uint32_t                ow_count;
	enum blk_zone_type	type:2;
	enum blk_zone_cond	cond:4;
	unsigned int		open:1;
	unsigned int		reset_zone:1;
#endif
};

/**
 * zoned_block_device_info - zoned block device characteristics
 * @model: Device model.
 * @mutex: Protects the modifiable members in this structure (refcount and
 *		num_open_zones).
 * @zone_size: size of a single zone in units of 512 bytes
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
	enum blk_zoned_model	model;
	pthread_mutex_t		mutex;
	uint64_t		zone_size;
	uint64_t		sectors_with_data;
	uint32_t		zone_size_log2;
	uint32_t		nr_zones;
	uint32_t		refcount;
	uint32_t		num_open_zones;
	uint32_t		write_cnt;
	uint32_t		open_zones[FIO_MAX_OPEN_ZBD_ZONES];
	uint32_t		ow_blk_count; // overwrites to be done in blocks per zone
	uint32_t                ow_blk_interval; // interval between overwrites
	struct fio_zone_info	zone_info[0];
};

struct nvme_lbaf {
	uint16_t			ms;
	uint8_t			ds;
	uint8_t			rp;
};

struct nvme_id_ns {
	uint64_t			nsze;
	uint64_t			ncap;
	uint64_t			nuse;
	uint8_t			nsfeat;
	uint8_t			nlbaf;
	uint8_t			flbas;
	uint8_t			mc;
	uint8_t			dpc;
	uint8_t			dps;
	uint8_t			nmic;
	uint8_t			rescap;
	uint8_t			fpi;
	uint8_t			dlfeat;
	uint16_t			nawun;
	uint16_t			nawupf;
	uint16_t			nacwu;
	uint16_t			nabsn;
	uint16_t			nabo;
	uint16_t			nabspf;
	uint16_t			noiob;
	uint8_t				nvmcap[16];
	uint16_t			npwg;
	uint16_t			npwa;
	uint16_t			npdg;
	uint16_t			npda;
	uint16_t			nows;
	uint8_t				rsvd74[18];
	uint32_t			anagrpid;
	uint8_t				rsvd96[3];
	uint8_t				nsattr;
	uint16_t			nvmsetid;
	uint16_t			endgid;
	uint8_t				nguid[16];
	uint8_t				eui64[8];
	struct nvme_lbaf	lbaf[16];
	uint8_t				rsvd192[192];
	uint8_t				vs[3712];
};

struct nvme_zns_lbafe {
	uint64_t			zsze;
	uint8_t			zdes;
	uint8_t			rsvd9[7];
};

struct nvme_id_ns_zns {
	uint16_t			zoc;
	uint16_t			ozcs;
	uint32_t			mar;
	uint32_t			mor;
	uint32_t			rrl;
	uint32_t			frl;
	uint8_t				rsvd20[20];
	uint16_t			zrwas;
	uint32_t			zrwacg;
	uint32_t			micws;
	uint8_t	 			rsvd50[2766];
	struct nvme_zns_lbafe	lbafe[16];
	uint8_t				rsvd3072[768];
	uint8_t 			vs[256];
} __attribute__((packed));

struct nvme_id_ns_zns_2 {
	uint16_t             zoc;
	uint16_t             ozcs;
	uint8_t              rsvd4[12];
	uint32_t             mar;
	uint32_t             mor;
	uint8_t              rsvd24[8];
	uint32_t             rrl;
	uint32_t                  frl;
	uint16_t                  zrwas;
	uint32_t                  zrwacg;
	uint32_t                  micws;
	uint8_t                    rsvd50[3534];
	struct nvme_zns_lbafe   lbafe[16];
	uint8_t                    vs[256];
} __attribute__((packed));


#define NVME_IOCTL_ADMIN_CMD	_IOWR('N', 0x41, struct nvme_admin_cmd)

#ifdef CONFIG_LINUX_BLKZONED
void zbd_free_zone_info(struct fio_file *f);
int zbd_init(struct thread_data *td);
void zbd_file_reset(struct thread_data *td, struct fio_file *f);
bool zbd_unaligned_write(int error_code);
void setup_zbd_zone_mode(struct thread_data *td, struct io_u *io_u);
enum io_u_action zbd_adjust_block(struct thread_data *td, struct io_u *io_u);
char *zbd_write_status(const struct thread_stat *ts);
bool zbd_issue_exp_open_zrwa(const struct fio_file *f, uint32_t zone_idx,
						uint32_t nsid);

static inline void zbd_queue_io_u(struct io_u *io_u, enum fio_q_status status)
{
	if (io_u->zbd_queue_io) {
		io_u->zbd_queue_io(io_u, status, io_u->error == 0);
		io_u->zbd_queue_io = NULL;
	}
}

static inline void zbd_put_io_u(struct io_u *io_u)
{
	if (io_u->zbd_put_io) {
		io_u->zbd_put_io(io_u);
		io_u->zbd_queue_io = NULL;
		io_u->zbd_put_io = NULL;
	}
}

#else
static inline void zbd_free_zone_info(struct fio_file *f)
{
}

static inline int zbd_init(struct thread_data *td)
{
	return 0;
}

static inline void zbd_file_reset(struct thread_data *td, struct fio_file *f)
{
}

static inline bool zbd_unaligned_write(int error_code)
{
	return false;
}

static inline enum io_u_action zbd_adjust_block(struct thread_data *td,
						struct io_u *io_u)
{
	return io_u_accept;
}

static inline char *zbd_write_status(const struct thread_stat *ts)
{
	return NULL;
}

static inline void zbd_queue_io_u(struct io_u *io_u,
				  enum fio_q_status status) {}
static inline void zbd_put_io_u(struct io_u *io_u) {}

static inline void setup_zbd_zone_mode(struct thread_data *td,
					struct io_u *io_u)
{
}

bool zbd_issue_exp_open_zrwa(const struct fio_file *f, uint32_t zone_idx,
					uint32_t nsid)
{
	return 0;
}

#endif

#endif /* FIO_ZBD_H */
