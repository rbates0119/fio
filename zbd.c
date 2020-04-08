/*
 * Copyright (C) 2018 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "file.h"
#include "fio.h"
#include "lib/pow2.h"
#include "log.h"
#include "oslib/asprintf.h"
#include "smalloc.h"
#include "verify.h"
#include "zbd.h"

static int g_finish_zone;
static int g_nsid;
static unsigned long long g_commit_gran;
static int g_exp_commit;
static int g_ow;
static unsigned int g_max_open_zones;
static unsigned int g_open_zones;
static unsigned int g_mar;
static bool g_init_done = false;

#define NVME_ZONE_LBA_SHIFT		12

/**
 * zbd_get_zoned_model - Get a device zoned model
 * @td: FIO thread data
 * @f: FIO file for which to get model information
 */
int zbd_get_zoned_model(struct thread_data *td, struct fio_file *f,
			enum zbd_zoned_model *model)
{
	int ret;

	if (td->io_ops && td->io_ops->get_zoned_model)
		ret = td->io_ops->get_zoned_model(td, f, model);
	else
		ret = blkzoned_get_zoned_model(td, f, model);
	if (ret < 0) {
		td_verror(td, errno, "get zoned model failed");
		log_err("%s: get zoned model failed (%d).\n",
			f->file_name, errno);
	}

	return ret;
}

/**
 * zbd_report_zones - Get zone information
 * @td: FIO thread data.
 * @f: FIO file for which to get zone information
 * @offset: offset from which to report zones
 * @zones: Array of struct zbd_zone
 * @nr_zones: Size of @zones array
 *
 * Get zone information into @zones starting from the zone at offset @offset
 * for the device specified by @f.
 *
 * Returns the number of zones reported upon success and a negative error code
 * upon failure. If the zone report is empty, always assume an error (device
 * problem) and return -EIO.
 */
int zbd_report_zones(struct thread_data *td, struct fio_file *f,
		     uint64_t offset, struct zbd_zone *zones,
		     unsigned int nr_zones)
{
	int ret;

	if (td->io_ops && td->io_ops->report_zones)
		ret = td->io_ops->report_zones(td, f, offset, zones, nr_zones);
	else
		ret = blkzoned_report_zones(td, f, offset, zones, nr_zones);
	if (ret < 0) {
		td_verror(td, errno, "report zones failed");
		log_err("%s: report zones from sector %llu failed (%d).\n",
			f->file_name, (unsigned long long)offset >> 9, errno);
	} else if (ret == 0) {
		td_verror(td, errno, "Empty zone report");
		log_err("%s: report zones from sector %llu is empty.\n",
			f->file_name, (unsigned long long)offset >> 9);
		ret = -EIO;
	}

	return ret;
}

/**
 * zbd_reset_wp - reset the write pointer of a range of zones
 * @td: FIO thread data.
 * @f: FIO file for which to reset zones
 * @offset: Starting offset of the first zone to reset
 * @length: Length of the range of zones to reset
 *
 * Reset the write pointer of all zones in the range @offset...@offset+@length.
 * Returns 0 upon success and a negative error code upon failure.
 */
int zbd_reset_wp(struct thread_data *td, const struct fio_file *f,
		 uint64_t offset, uint64_t length)
{
	int ret;

	if (td->io_ops && td->io_ops->reset_wp)
		ret = td->io_ops->reset_wp(td, f, offset, length);
	else
		ret = blkzoned_reset_wp(td, f, offset, length);
	if (ret < 0) {
		td_verror(td, errno, "resetting wp failed");
		log_err("%s: resetting wp for %llu sectors at sector %llu failed (%d).\n",
			f->file_name, (unsigned long long)length >> 9,
			(unsigned long long)offset >> 9, errno);
	}

	return ret;
}


/**
 * zbd_zone_idx - convert an offset into a zone number
 * @f: file pointer.
 * @offset: offset in bytes. If this offset is in the first zone_size bytes
 *	    past the disk size then the index of the sentinel is returned.
 */
static uint32_t zbd_zone_idx(const struct fio_file *f, uint64_t offset)
{
	uint32_t zone_idx;

	if (f->zbd_info->zone_size_log2 > 0)
		zone_idx = offset >> f->zbd_info->zone_size_log2;
	else
		zone_idx = offset / f->zbd_info->zone_size;

	return min(zone_idx, f->zbd_info->nr_zones);
}

/**
 * zbd_zone_swr - Test whether a zone requires sequential writes
 * @z: zone info pointer.
 */
static inline bool zbd_zone_swr(struct fio_zone_info *z)
{
	return z->type == ZBD_ZONE_TYPE_SWR;
}

/**
 * zbd_zone_full - verify whether a minimum number of bytes remain in a zone
 * @f: file pointer.
 * @z: zone info pointer.
 * @required: minimum number of bytes that must remain in a zone.
 *
 * The caller must hold z->mutex.
 */
static bool zbd_zone_full(const struct fio_file *f, struct fio_zone_info *z,
			  uint64_t required)
{
	bool full = false;

	assert((required & 511) == 0);
	full = (zbd_zone_swr(z) &&
		(z->wp + required > z->start + z->capacity)) || z->cond == ZBD_ZONE_COND_FULL;
	if (full) z->cond = ZBD_ZONE_COND_FULL;

	return  full;
}

static void zone_lock(struct thread_data *td, struct fio_zone_info *z)
{
	/*
	 * Lock the io_u target zone. The zone will be unlocked if io_u offset
	 * is changed or when io_u completes and zbd_put_io() executed.
	 * To avoid multiple jobs doing asynchronous I/Os from deadlocking each
	 * other waiting for zone locks when building an io_u batch, first
	 * only trylock the zone. If the zone is already locked by another job,
	 * process the currently queued I/Os so that I/O progress is made and
	 * zones unlocked.
	 */
	if (pthread_mutex_trylock(&z->mutex) != 0) {
		if (!td_ioengine_flagged(td, FIO_SYNCIO))
			io_u_quiesce(td);
		pthread_mutex_lock(&z->mutex);
	}
}

static bool is_valid_offset(const struct fio_file *f, uint64_t offset)
{
	return (uint64_t)(offset - f->file_offset) < f->io_size;
}

/* Verify whether direct I/O is used for all host-managed zoned drives. */
static bool zbd_using_direct_io(void)
{
	struct thread_data *td;
	struct fio_file *f;
	int i, j;

	for_each_td(td, i) {
		if (td->o.odirect || !(td->o.td_ddir & TD_DDIR_WRITE))
			continue;
		for_each_file(td, f, j) {
			if (f->zbd_info &&
			    f->zbd_info->model == ZBD_HOST_MANAGED)
				return false;
		}
	}

	return true;
}

/* Whether or not the I/O range for f includes one or more sequential zones */
static bool zbd_is_seq_job(struct fio_file *f)
{
	uint32_t zone_idx, zone_idx_b, zone_idx_e;

	assert(f->zbd_info);
	if (f->io_size == 0)
		return false;
	zone_idx_b = zbd_zone_idx(f, f->file_offset);
	zone_idx_e = zbd_zone_idx(f, f->file_offset + f->io_size - 1);
	for (zone_idx = zone_idx_b; zone_idx <= zone_idx_e; zone_idx++)
		if (zbd_zone_swr(&f->zbd_info->zone_info[zone_idx]))
			return true;

	return false;
}

/*
 * Verify whether offset and size parameters are aligned with zone boundaries.
 */
static bool zbd_verify_sizes(void)
{
	const struct fio_zone_info *z;
	struct thread_data *td;
	struct fio_file *f;
	uint64_t new_offset, new_end;
	uint32_t zone_idx;
	int i, j;

	for_each_td(td, i) {
		for_each_file(td, f, j) {
			if (!f->zbd_info)
				continue;
			if (f->file_offset >= f->real_file_size)
				continue;
			if (!zbd_is_seq_job(f))
				continue;

			if (!td->o.zone_size) {
				td->o.zone_size = f->zbd_info->zone_size;
				if (!td->o.zone_size) {
					log_err("%s: invalid 0 zone size\n",
						f->file_name);
					return false;
				}
			} else if (td->o.zone_size != f->zbd_info->zone_size) {
				log_err("%s: job parameter zonesize %llu does not match disk zone size %llu.\n",
					f->file_name, (unsigned long long) td->o.zone_size,
					(unsigned long long) f->zbd_info->zone_size);
				return false;
			}

			if (td->o.zone_skip &&
			    (td->o.zone_skip < td->o.zone_size ||
			     td->o.zone_skip % td->o.zone_size)) {
				log_err("%s: zoneskip %llu is not a multiple of the device zone size %llu.\n",
					f->file_name, (unsigned long long) td->o.zone_skip,
					(unsigned long long) td->o.zone_size);
				return false;
			}

			zone_idx = zbd_zone_idx(f, f->file_offset);
			z = &f->zbd_info->zone_info[zone_idx];
			if (f->file_offset != z->start) {
				new_offset = (z+1)->start;
				if (new_offset >= f->file_offset + f->io_size) {
					log_info("%s: io_size must be at least one zone\n",
						 f->file_name);
					return false;
				}
				log_info("%s: rounded up offset from %llu to %llu\n",
					 f->file_name, (unsigned long long) f->file_offset,
					 (unsigned long long) new_offset);
				f->io_size -= (new_offset - f->file_offset);
				f->file_offset = new_offset;
			}
			zone_idx = zbd_zone_idx(f, f->file_offset + f->io_size);
			z = &f->zbd_info->zone_info[zone_idx];
			new_end = z->start;
			if (f->file_offset + f->io_size != new_end) {
				if (new_end <= f->file_offset) {
					log_info("%s: io_size must be at least one zone\n",
						 f->file_name);
					return false;
				}
				log_info("%s: rounded down io_size from %llu to %llu\n",
					 f->file_name, (unsigned long long) f->io_size,
					 (unsigned long long) new_end - f->file_offset);
				f->io_size = new_end - f->file_offset;
			}
		}
	}

	return true;
}

static bool zbd_verify_bs(void)
{
	struct thread_data *td;
	struct fio_file *f;
	uint32_t zone_size;
	int i, j, k;

	for_each_td(td, i) {
		for_each_file(td, f, j) {
			if (!f->zbd_info)
				continue;
			zone_size = f->zbd_info->zone_size;
			for (k = 0; k < ARRAY_SIZE(td->o.bs); k++) {
				if (td->o.verify != VERIFY_NONE &&
				    zone_size % td->o.bs[k] != 0) {
					log_info("%s: block size %llu is not a divisor of the zone size %d\n",
						 f->file_name, td->o.bs[k],
						 zone_size);
					return false;
				}
			}
		}
	}
	// todo: handle bs[0] properly
	if (td->o.bs[1] > g_commit_gran &&
			(td->o.bs[1] % g_commit_gran)) {
		log_info("Block size should be multiple of commit granularity \n");
		return false;
	}
	return true;
}

static int ilog2(uint64_t i)
{
	int log = -1;

	while (i) {
		i >>= 1;
		log++;
	}
	return log;
}

/*
 * Initialize f->zbd_info for devices that are not zoned block devices. This
 * allows to execute a ZBD workload against a non-ZBD device.
 */
static int init_zone_info(struct thread_data *td, struct fio_file *f)
{
	uint32_t nr_zones;
	struct fio_zone_info *p;
	uint64_t zone_size = td->o.zone_size;
	struct zoned_block_device_info *zbd_info = NULL;
	pthread_mutexattr_t attr;
	int i;

	if (zone_size == 0) {
		log_err("%s: Specifying the zone size is mandatory for regular block devices with --zonemode=zbd\n\n",
			f->file_name);
		return 1;
	}

	if (zone_size < 512) {
		log_err("%s: zone size must be at least 512 bytes for --zonemode=zbd\n\n",
			f->file_name);
		return 1;
	}

	nr_zones = (f->real_file_size + zone_size - 1) / zone_size;
	zbd_info = scalloc(1, sizeof(*zbd_info) +
			   (nr_zones + 1) * sizeof(zbd_info->zone_info[0]));
	if (!zbd_info)
		return -ENOMEM;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutexattr_setpshared(&attr, true);
	pthread_mutex_init(&zbd_info->mutex, &attr);
	zbd_info->refcount = 1;
	p = &zbd_info->zone_info[0];
	for (i = 0; i < nr_zones; i++, p++) {
		pthread_mutex_init(&p->mutex, &attr);
		p->start = i * zone_size;
		p->wp = p->start + zone_size;
		p->type = ZBD_ZONE_TYPE_SWR;
		p->cond = ZBD_ZONE_COND_EMPTY;
	}
	/* a sentinel */
	p->start = nr_zones * zone_size;

	f->zbd_info = zbd_info;
	f->zbd_info->zone_size = zone_size;
	f->zbd_info->zone_size_log2 = is_power_of_2(zone_size) ?
		ilog2(zone_size) : 0;
	f->zbd_info->nr_zones = nr_zones;
	pthread_mutexattr_destroy(&attr);
	return 0;
}

bool zbd_verify_scheduler(const char *file_name, const char *scheduler) {

	char *dev;
	char path[40];
	char *scheduler_str;
	bool correct = false;

	dev = strstr(file_name, "nvme");

	if (dev != NULL) {

		sprintf(path, "/sys/block/%s/queue/scheduler", dev);
		scheduler_str = read_file(path);
		if (scheduler_str != NULL) {
			dprint(FD_ZBD, "zbd_verify_scheduler:  %s, %s, %s\n", scheduler, scheduler_str, path);
			correct =  (strstr(scheduler_str, scheduler) != NULL);
			if (!correct) {
				log_err("fio: %s not using correct scheduler. %s\n", file_name, scheduler_str);
			}
		}
	}

	return correct;
}

/*
 * Maximum number of zones to report in one operation.
 */
#define ZBD_REPORT_MAX_ZONES	8192U

/*
 * Parse the device zone report and store it in f->zbd_info. Must be called
 * only for devices that are zoned, namely those with a model != ZBD_NONE.
 */
static int parse_zone_info(struct thread_data *td, struct fio_file *f)
{
	int nr_zones, nrz;
	struct zbd_zone *zones, *z;
	struct fio_zone_info *p;
	uint64_t zone_size, offset;
	struct zoned_block_device_info *zbd_info = NULL;
	pthread_mutexattr_t attr;
	int i, j, ns_id = 0, bs, ret = 0;
	void *zone_q_buf = NULL;
	struct nvme_id_ns_zns_2 *ns_zns = NULL;
	struct nvme_id_ns *ns = NULL;
	char scheduler[15];
	struct thread_data *td2;
	uint32_t zrwas, zone_io_q_size = 0;
	bool set_cond = true;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutexattr_setpshared(&attr, true);

	zones = calloc(ZBD_REPORT_MAX_ZONES, sizeof(struct zbd_zone));
	if (!zones)
		goto out;
	ns_zns = calloc(1,4096);
	if (!ns_zns)
		goto out;
	ns = calloc(1,4096);
	if (!ns)
		goto out;

	if (!g_init_done) {
		i=0;

		ns_id = zbd_get_nsid(f);
		g_nsid = ns_id;

		for_each_td(td2, i) {

			if (td2->o.zone_mode==ZONE_MODE_ZBD)
				g_max_open_zones += td2->o.max_open_zones;

			if (td->o.zrwa_alloc) {

				if (td2->o.ns_id > 0) {
					if (ns_id > 0)
					{
						if (ns_id != td2->o.ns_id) {
							log_err("fio: %s job parameter ns_id = %u does not match device ns = %u.\n",
								f->file_name, td2->o.ns_id, ns_id);
							ret = -EINVAL;
							goto out;
						}
					} else {
						log_err("fio: %s could not get device namespace id.\n",
							f->file_name);
						ret = -EINVAL;
						goto out;
					}
				} else {
					if (ns_id > 0) {
						td2->o.ns_id = ns_id;
					} else {
						log_err("fio: %s job parameter ns_id = %u does not match device ns = %u.\n",
								f->file_name, td2->o.ns_id, ns_id);
						ret = -EINVAL;
						goto out;
					}
				}
			}
			dprint(FD_ZBD, "parse_zone_info: id = %d, max_zones = %d, td->o.ns_id = %d, ns_id = %d\n",
					td2->thread_number, g_max_open_zones, td2->o.ns_id, ns_id);
		}

		if (td->o.reset_all_zones_first) {
			if (!zbd_zone_reset(td, f, 0x00, true, g_nsid))
				dprint(FD_ZBD, "parse_zone_info: reset zones failed \n");
			td->o.reset_all_zones_first = false;
		}
		g_init_done = true;
	}

	nrz = zbd_report_zones(td, f, 0, zones, ZBD_REPORT_MAX_ZONES);
	if (nrz < 0) {
		ret = nrz;
		log_info("fio: report zones (offset 0) failed for %s (%d).\n",
			 f->file_name, -ret);
		goto out;
	}

	zone_size = zones[0].len;
	nr_zones = (f->real_file_size + zone_size - 1) / zone_size;

	if (td->o.zone_size == 0) {
		td->o.zone_size = zone_size;
	} else if (td->o.zone_size != zone_size) {
		log_err("fio: %s job parameter zonesize %llu does not match disk zone size %llu.\n",
			f->file_name, (unsigned long long) td->o.zone_size,
			(unsigned long long) zone_size);
		ret = -EINVAL;
		goto out;
	}

	dprint(FD_ZBD, "Device %s has %d zones of size %llu KB\n", f->file_name,
	       nr_zones, (unsigned long long) zone_size / 1024);

	zbd_info = scalloc(1, sizeof(*zbd_info) +
			   (nr_zones + 1) * sizeof(zbd_info->zone_info[0]));
	ret = -ENOMEM;
	if (!zbd_info)
		goto out;
	pthread_mutex_init(&zbd_info->mutex, &attr);

	zbd_info->refcount = 1;
	p = &zbd_info->zone_info[0];

	zbd_info->zones_io_q_buf = NULL;
	if (td->o.zrwa_alloc && td->o.dynamic_qd && (td->o.td_ddir & TD_DDIR_WRITE)) {
		zone_io_q_size = sizeof(uint64_t) * (td->o.iodepth + 1);
		zone_q_buf = scalloc(1, zone_io_q_size * nr_zones);

		if (!zone_q_buf)
			goto out;
		zbd_info->zones_io_q_buf = zone_q_buf;
	}

	for (offset = 0, j = 0; j < nr_zones;) {
		z = &zones[0];
		for (i = 0; i < nrz; i++, j++, z++, p++) {
			pthread_mutex_init(&p->mutex, &attr);
			p->start = z->start;
			p->capacity = z->capacity;
			if (td->o.zrwa_alloc && td->o.dynamic_qd && (td->o.td_ddir & TD_DDIR_WRITE)) {
				p->zone_io_q = zone_q_buf + (j * zone_io_q_size); // j is zone-idx
				p->last_io = 0;
			}
			switch (z->cond) {
			case ZBD_ZONE_COND_NOT_WP:
			case ZBD_ZONE_COND_FULL:
				p->wp = p->start + zone_size;
				break;
			case ZBD_ZONE_COND_IMP_OPEN:
			case ZBD_ZONE_COND_EXP_OPEN:
				if (td->o.reset_active_zones_first) {
					if (!zbd_zone_reset(td, f, p->start, false, g_nsid))	{
						td_verror(td, errno, "resetting wp failed");
						log_err("%s: resetting wp 0x%lX failed (%d).\n",
							f->file_name, p->start, errno);
						ret = -1;
						goto out;
					} else {
						assert(z->start <= z->wp);
						assert(z->wp <= z->start + zone_size);
						p->cond = ZBD_ZONE_COND_EMPTY;
						set_cond = false;
						p->wp = z->start;
						p->dev_wp = z->start;
					}
				} else {
					assert(z->start <= z->wp);
					assert(z->wp <= z->start + zone_size);
					p->wp = z->wp;
					if ((g_max_open_zones > 0) && !td->o.reset_all_zones_first) {
						td->o.open_zones[td->o.num_open_zones++] = j;
						g_open_zones++;
						p->open = 1;
						assert(td->o.num_open_zones <= td->o.max_open_zones);
					}
				}
				break;
			case ZBD_ZONE_COND_CLOSED:
				if (td->o.reset_active_zones_first) {
					if (!zbd_zone_reset(td, f, p->start, false, g_nsid))	{
						td_verror(td, errno, "resetting wp failed");
						log_err("%s: resetting wp 0x%lX failed (%d).\n",
							f->file_name, p->start, errno);
						ret = -1;
						goto out;
					} else {
						assert(z->start <= z->wp);
						assert(z->wp <= z->start + zone_size);
						p->cond = ZBD_ZONE_COND_EMPTY;
						set_cond = false;
						p->wp = z->start;
						p->dev_wp = z->start;
					}
				}
				break;
			default:
				assert(z->start <= z->wp);
				assert(z->wp <= z->start + zone_size);
				p->wp = z->wp;
				break;
			}
			p->type = z->type;
			if (set_cond)
				p->cond = z->cond;
			else
				set_cond = true;
			if (j > 0 && p->start != p[-1].start + zone_size) {
				log_info("%s: invalid zone data\n",
					 f->file_name);
				ret = -EINVAL;
				goto out;
			}
		}
		z--;
		offset = z->start + z->len;
		if (j >= nr_zones)
			break;
		nrz = zbd_report_zones(td, f, offset,
					    zones, ZBD_REPORT_MAX_ZONES);
		if (nrz < 0) {
			ret = nrz;
			log_info("fio: report zones (offset %llu) failed for %s (%d).\n",
			 	 (unsigned long long)offset,
				 f->file_name, -ret);
			goto out;
		}
	}

	if (zbd_identify_ns(td, f, ns, ns_zns, g_nsid)) {
		bs = 4096;
		for (i = 0; i <= ns->nlbaf; i++) {
			if (ns->flbas & 0xf)
				bs = ns->lbaf[i].ds;
		}
		if (ns_zns->mar > 0)
		{
			g_mar = ns_zns->mar;
		} else {
			g_mar = ((struct nvme_id_ns_zns*)ns_zns)->mar;
		}
		if (g_max_open_zones > (g_mar + 1))
		{
			log_err("fio: %s job parameter max_open_zones = %u is greater than maximum active resources = %llu (zero based).\n",
				f->file_name, g_max_open_zones, (unsigned long long)g_mar);
			ret = -EINVAL;
			goto out;
		}
		dprint(FD_ZBD, "parse_zone_info: zrwas = %d, bs = %d \n", le16_to_cpu(ns_zns->zrwas), bs);
		if (ns_zns->zrwas > 0) {
			zrwas = ns_zns->zrwas;
		} else {
			zrwas = ((struct nvme_id_ns_zns*)ns_zns)->zrwas;
		}
		dprint(FD_ZBD, "parse_zone_info: g_mar = %d\n", g_mar);
		if (td->o.zrwa_alloc) {
			if (td_write(td) && !td->o.dynamic_qd) {
				if ((zrwas * bs) <  (td->o.bs[1] * td->o.iodepth)) {
					log_err("fio: %s iodepth = %d * blocksize = %lld (%lld) is greater than zrwas = %d \n",
						f->file_name, td->o.iodepth, td->o.bs[1], (td->o.iodepth * td->o.bs[1]), (zrwas * bs));
					ret = -EINVAL;
					goto out;
				}
			}
		}
	} else {
		dprint(FD_ZBD, "parse_zone_info: identify failed id = %d \n", td->thread_number);
		g_mar = 11;
	}
	if (td->o.zrwa_alloc) {
		if (td_write(td)) {
			if (!td->o.issue_zone_finish && td_write(td)) {
				log_err("fio: %s job parameter issue_zone_finish not set. Must be set if zrwa_alloc is set\n",
				f->file_name);
				ret = -EINVAL;
				goto out;
			}
			sprintf(scheduler, "[none]");
			if (!zbd_verify_scheduler(f->file_name, scheduler)) {
				goto out;
			}
		}
	}  else {
		sprintf(scheduler, "[mq-deadline]");
		if (!zbd_verify_scheduler(f->file_name, scheduler))
			goto out;
	}

	/* a sentinel */
	zbd_info->zone_info[nr_zones].start = offset;

	f->zbd_info = zbd_info;
	f->zbd_info->zone_size = zone_size;
	f->zbd_info->zone_size_log2 = is_power_of_2(zone_size) ?
		ilog2(zone_size) : 0;
	f->zbd_info->nr_zones = nr_zones;
	zbd_info = NULL;
	ret = 0;
	g_finish_zone = td->o.issue_zone_finish;

out:
	sfree(zbd_info);
	free(zones);
	free(ns);
	free(ns_zns);

	pthread_mutexattr_destroy(&attr);
	return ret;
}

/*
 * Allocate zone information and store it into f->zbd_info if zonemode=zbd.
 *
 * Returns 0 upon success and a negative error code upon failure.
 */
static int zbd_create_zone_info(struct thread_data *td, struct fio_file *f)
{
	enum zbd_zoned_model zbd_model;
	int ret;

	assert(td->o.zone_mode == ZONE_MODE_ZBD);

	ret = zbd_get_zoned_model(td, f, &zbd_model);
	if (ret)
		return ret;

	switch (zbd_model) {
	case ZBD_IGNORE:
		return 0;
	case ZBD_HOST_AWARE:
	case ZBD_HOST_MANAGED:
		ret = parse_zone_info(td, f);
		break;
	case ZBD_NONE:
		ret = init_zone_info(td, f);
		break;
	default:
		td_verror(td, EINVAL, "Unsupported zoned model");
		log_err("Unsupported zoned model\n");
		return -EINVAL;
	}

	if (ret == 0)
		f->zbd_info->model = zbd_model;
	return ret;
}

void zbd_free_zone_info(struct fio_file *f)
{
	uint32_t refcount;

	if (!f->zbd_info)
		return;

	pthread_mutex_lock(&f->zbd_info->mutex);
	refcount = --f->zbd_info->refcount;
	pthread_mutex_unlock(&f->zbd_info->mutex);

	assert((int32_t)refcount >= 0);
	if (refcount == 0) {
		sfree(f->zbd_info->zones_io_q_buf);
		sfree(f->zbd_info);
	}
	f->zbd_info = NULL;
}

/*
 * Initialize f->zbd_info.
 *
 * Returns 0 upon success and a negative error code upon failure.
 *
 * Note: this function can only work correctly if it is called before the first
 * fio fork() call.
 */
static int zbd_init_zone_info(struct thread_data *td, struct fio_file *file)
{
	struct thread_data *td2;
	struct fio_file *f2;
	int i, j, ret;

	for_each_td(td2, i) {
		for_each_file(td2, f2, j) {
			if (td2 == td && f2 == file)
				continue;
			if (!f2->zbd_info ||
			    strcmp(f2->file_name, file->file_name) != 0)
				continue;
			file->zbd_info = f2->zbd_info;
			file->zbd_info->refcount++;
			return 0;
		}
	}

	ret = zbd_create_zone_info(td, file);
	if (ret < 0)
		td_verror(td, -ret, "zbd_create_zone_info() failed");
	return ret;
}

// Set the divisor so that the writes are as random as possible, without
// failing to perform the desired number of overwrites.
static uint32_t get_divisor(uint32_t overwrite_percentage) {

	if (overwrite_percentage >= 50) {
		return 2;
	} else if ((overwrite_percentage >= 25) && (overwrite_percentage < 50)) {
		return 3;
	} else if ((overwrite_percentage > 10) && (overwrite_percentage < 25)) {
		return 4;
	} else if ((overwrite_percentage > 5) && (overwrite_percentage <= 10)) {
		return 5;
	} else {
		return 10;
	}
}

int zbd_init(struct thread_data *td)
{
	struct fio_file *f = NULL;
	int i, start_z_idx, nr_zones;
	unsigned long long total_ow, ow_blks_per_zone;

	for_each_file(td, f, i) {
		if (zbd_init_zone_info(td, f))
			return 1;
	}

	if (!zbd_using_direct_io()) {
		log_err("Using direct I/O is mandatory for writing to ZBD drives\n\n");
		return 1;
	}

	if (td->o.exp_commit || td->o.zrwa_overwrite_percent) {
		if (!td->o.zrwa_alloc) {
			log_err("zone needs to be opened with zrwa_alloc for zrwa operations\n\n");
			return 1;
		}
	}

	g_ow = td->o.zrwa_overwrite_percent;
	g_commit_gran = td->o.commit_gran;
	g_exp_commit = td->o.exp_commit;
	if (td->o.exp_commit && td->o.bs[1] > 1048576) {
		log_err("Block size must be less than 1MB with exp commit\n\n");
		return 1;
	}

	if (td->o.zrwa_overwrite_percent && td->o.exp_commit) {
		log_err("Explicit commit not supported with zrwa overwrite option \n");
		return 1;
	}

	if ((td->o.finish_zone_pct < 100) && !td->o.issue_zone_finish) {
		log_err("finish_zone_pct not supported without issue_zone_finish option \n");
		return 1;
	}

	if (!zbd_verify_sizes())
		return 1;

	if (!zbd_verify_bs())
		return 1;
	if (td->o.zrwa_overwrite_percent) {
		// Translate the percent to number of blocks to be
		// overwritten per zone. Based on the size, get the
		// number of zones in the range. Find the number of
		// bytes to be written extra based on num of zones
		// If run time is specified, don't modify io_size
		// as that can stop the workload after io_size bytes
		// before the time is completed. Issue ow_blks_per_zone
		// extra IOs to each zone.
		ow_blks_per_zone = ((f->zbd_info->zone_info[0].capacity / td->o.bs[1]) *
					td->o.zrwa_overwrite_percent) / 100;
		td->zbd_ow_blk_interval = (f->zbd_info->zone_info[0].capacity / td->o.bs[1]) / ow_blks_per_zone;
		// Handle case where ow % is greater than 100
		if (td->o.zrwa_overwrite_percent > 100)
			td->zbd_ow_blk_interval = 1;

		start_z_idx = zbd_zone_idx(f, f->file_offset);
		nr_zones = zbd_zone_idx(f, f->io_size) - start_z_idx;
		total_ow = nr_zones * ow_blks_per_zone * td->o.bs[1];
		td->o.zrwa_divisor = get_divisor(td->o.zrwa_overwrite_percent);
		dprint(FD_ZBD, "zbd_init: Overwrites per zone = %lld, total ow bytes = %lld, nr_zones = %d,  overwrites every %u blocks\n",
						ow_blks_per_zone, total_ow, nr_zones, td->zbd_ow_blk_interval);
		dprint(FD_ZBD, "zbd_init: io_size 0 %lld\n", td->o.io_size);
		if ((!td->o.timeout) && (td->o.io_size > 0)) {
			td->o.io_size += total_ow;
		}
		td->zbd_ow_blk_count = ow_blks_per_zone;
		dprint(FD_ZBD, "zbd_init: new io_size with overwrites = %lld, ow-count-in-blks-per-zone = %u \n",
							td->o.io_size, td->zbd_ow_blk_count);
	}

	return 0;
}

int full_zones(const struct fio_file *f) {
	struct fio_zone_info *z;
	int num_full_zones = 0;
	int i;

	z = &f->zbd_info->zone_info[0];
	for (i = 0; i < f->zbd_info->nr_zones; i++, z++) {
		if (z->cond == ZBD_ZONE_COND_FULL) num_full_zones++;
	}

	return num_full_zones;
}

/* The caller must hold f->zbd_info->mutex. */
static bool is_zone_open(const struct thread_data *td, unsigned int zone_idx)
{
	int i;

	assert(g_max_open_zones <= ARRAY_SIZE(td->o.open_zones));
	assert(td->o.num_open_zones <= td->o.max_open_zones);

	for (i = 0; i < td->o.num_open_zones; i++)
		if (td->o.open_zones[i] == zone_idx)
			return true;

	return false;
}

/**
 * zbd_reset_range - reset zones for a range of sectors
 * @td: FIO thread data.
 * @f: Fio file for which to reset zones
 * @sector: Starting sector in units of 512 bytes
 * @nr_sectors: Number of sectors in units of 512 bytes
 *
 * Returns 0 upon success and a negative error code upon failure.
 */
static int zbd_reset_range(struct thread_data *td, const struct fio_file *f,
			   uint64_t offset, uint64_t length)
{
	uint32_t zone_idx_b, zone_idx_e;
	struct fio_zone_info *zb, *ze, *z;
	int ret = 0;

	assert(is_valid_offset(f, offset + length - 1));
	switch (f->zbd_info->model) {
	case ZBD_HOST_AWARE:
	case ZBD_HOST_MANAGED:
		ret = zbd_reset_wp(td, f, offset, length);
		if (ret < 0)
			return ret;
		break;
	default:
		break;
	}

	zone_idx_b = zbd_zone_idx(f, offset);
	zb = &f->zbd_info->zone_info[zone_idx_b];
	zone_idx_e = zbd_zone_idx(f, offset + length);
	ze = &f->zbd_info->zone_info[zone_idx_e];
	for (z = zb; z < ze; z++) {
		pthread_mutex_lock(&z->mutex);
		pthread_mutex_lock(&f->zbd_info->mutex);
		f->zbd_info->sectors_with_data -= z->wp - z->start;
		pthread_mutex_unlock(&f->zbd_info->mutex);
		z->wp = z->start;
		z->dev_wp = z->start;
		z->verify_block = 0;
		z->cond = ZBD_ZONE_COND_EMPTY;
		zone_idx_b++;
		pthread_mutex_unlock(&z->mutex);
	}

	td->ts.nr_zone_resets += ze - zb;

	return ret;
}

static unsigned int zbd_zone_nr(struct zoned_block_device_info *zbd_info,
				struct fio_zone_info *zone)
{
	return zone - zbd_info->zone_info;
}

/**
 * zbd_reset_zone - reset the write pointer of a single zone
 * @td: FIO thread data.
 * @f: FIO file associated with the disk for which to reset a write pointer.
 * @z: Zone to reset.
 *
 * Returns 0 upon success and a negative error code upon failure.
 */
static int zbd_reset_zone(struct thread_data *td, const struct fio_file *f,
			  struct fio_zone_info *z)
{
	dprint(FD_ZBD, "%s: resetting wp of zone %u\n", f->file_name,
		zbd_zone_nr(f->zbd_info, z));

	return zbd_reset_range(td, f, z->start, (z+1)->start - z->start);
}

/*
 * Reset a range of zones. Returns 0 upon success and 1 upon failure.
 * @td: fio thread data.
 * @f: fio file for which to reset zones
 * @zb: first zone to reset.
 * @ze: first zone not to reset.
 * @all_zones: whether to reset all zones or only those zones for which the
 *	write pointer is not a multiple of td->o.min_bs[DDIR_WRITE].
 */
static int zbd_reset_zones(struct thread_data *td, struct fio_file *f,
			   struct fio_zone_info *const zb,
			   struct fio_zone_info *const ze, bool all_zones)
{
	struct fio_zone_info *z;
	const uint32_t min_bs = td->o.min_bs[DDIR_WRITE];
	bool reset_wp;
	int res = 0;

	assert(min_bs);

	dprint(FD_ZBD, "%s: examining zones %u .. %u\n", f->file_name,
		zbd_zone_nr(f->zbd_info, zb), zbd_zone_nr(f->zbd_info, ze));
	for (z = zb; z < ze; z++) {
		if (!zbd_zone_swr(z))
			continue;
		zone_lock(td, z);
		reset_wp = all_zones ? z->wp != z->start :
				(td->o.td_ddir & TD_DDIR_WRITE) &&
				z->wp % min_bs != 0;
		if (reset_wp) {
			dprint(FD_ZBD, "%s: resetting zone %u\n",
			       f->file_name,
			       zbd_zone_nr(f->zbd_info, z));
			if (zbd_reset_zone(td, f, z) < 0)
				res = 1;
		}
		pthread_mutex_unlock(&z->mutex);
	}

	return res;
}

/*
 * Reset zbd_info.write_cnt, the counter that counts down towards the next
 * zone reset.
 */
static void zbd_reset_write_cnt(const struct thread_data *td,
				const struct fio_file *f)
{
	assert(0 <= td->o.zrf.u.f && td->o.zrf.u.f <= 1);

	pthread_mutex_lock(&f->zbd_info->mutex);
	f->zbd_info->write_cnt = td->o.zrf.u.f ?
		min(1.0 / td->o.zrf.u.f, 0.0 + UINT_MAX) : UINT_MAX;
	pthread_mutex_unlock(&f->zbd_info->mutex);
}

static bool zbd_dec_and_reset_write_cnt(const struct thread_data *td,
					const struct fio_file *f)
{
	uint32_t write_cnt = 0;

	pthread_mutex_lock(&f->zbd_info->mutex);
	assert(f->zbd_info->write_cnt);
	if (f->zbd_info->write_cnt)
		write_cnt = --f->zbd_info->write_cnt;
	if (write_cnt == 0)
		zbd_reset_write_cnt(td, f);
	pthread_mutex_unlock(&f->zbd_info->mutex);

	return write_cnt == 0;
}

enum swd_action {
	CHECK_SWD,
	SET_SWD,
};

/* Calculate the number of sectors with data (swd) and perform action 'a' */
static uint64_t zbd_process_swd(const struct fio_file *f, enum swd_action a)
{
	struct fio_zone_info *zb, *ze, *z;
	uint64_t swd = 0;

	zb = &f->zbd_info->zone_info[zbd_zone_idx(f, f->file_offset)];
	ze = &f->zbd_info->zone_info[zbd_zone_idx(f, f->file_offset +
						  f->io_size)];
	for (z = zb; z < ze; z++) {
		pthread_mutex_lock(&z->mutex);
		swd += z->wp - z->start;
	}
	pthread_mutex_lock(&f->zbd_info->mutex);
	switch (a) {
	case CHECK_SWD:
		assert(f->zbd_info->sectors_with_data == swd);
		break;
	case SET_SWD:
		f->zbd_info->sectors_with_data = swd;
		break;
	}
	pthread_mutex_unlock(&f->zbd_info->mutex);
	for (z = zb; z < ze; z++)
		pthread_mutex_unlock(&z->mutex);

	return swd;
}

/*
 * The swd check is useful for debugging but takes too much time to leave
 * it enabled all the time. Hence it is disabled by default.
 */
static const bool enable_check_swd = false;

/* Check whether the value of zbd_info.sectors_with_data is correct. */
static void zbd_check_swd(const struct fio_file *f)
{
	if (!enable_check_swd)
		return;

	zbd_process_swd(f, CHECK_SWD);
}

static void zbd_init_swd(struct fio_file *f)
{
	uint64_t swd;

	if (!enable_check_swd)
		return;

	swd = zbd_process_swd(f, SET_SWD);
	dprint(FD_ZBD, "%s(%s): swd = %" PRIu64 "\n", __func__, f->file_name,
	       swd);
}

void zbd_file_reset(struct thread_data *td, struct fio_file *f)
{
	struct fio_zone_info *zb, *ze;
	uint32_t zone_idx_e;

	if (!f->zbd_info)
		return;

	zb = &f->zbd_info->zone_info[zbd_zone_idx(f, f->file_offset)];
	zone_idx_e = zbd_zone_idx(f, f->file_offset + f->io_size);
	ze = &f->zbd_info->zone_info[zone_idx_e];
	zbd_init_swd(f);

	/*
	 * If data verification is enabled reset the affected zones before
	 * writing any data to avoid that a zone reset has to be issued while
	 * writing data, which causes data loss.
	 */
	if (td->o.verify != VERIFY_NONE &&	(td->o.td_ddir & TD_DDIR_WRITE) &&
			td->runstate != TD_VERIFYING)
		zbd_reset_zones(td, f, zb, ze, true);
	zbd_reset_write_cnt(td, f);
}

#define ZRWA_SIZE_BYTES		1024 * 1024


uint64_t zbd_get_lowest_queued_offset(struct fio_zone_info *z,
					uint64_t io_offset)
{
	uint64_t low_off;
	int i;

	// zone_io_q[0] is always the lowest offset ??
	low_off = z->zone_io_q[0];

	for (i=0; i < z->io_q_count; i++) {
		if (low_off <= z->zone_io_q[i])
			continue;
		low_off = z->zone_io_q[i];
	}

	dprint(FD_ZBD, "zbd_get_lowest_queued_offset: oldest pending io %lu, io-offset= %lu fio-wp=%lu q-count = %u, diff = %lu\n",
			low_off, z->wp, io_offset, z->io_q_count, (io_offset - low_off));
	return low_off;
}

// Returning 0 will return BUSY for the IO and will be requeued.
unsigned int zbd_can_zrwa_queue_more(struct thread_data *td, const struct io_u *io_u)
{
	const struct fio_file *f = io_u->file;
	struct fio_zone_info *z;
	uint32_t zone_idx;

	// For reads no need to do zrwa check
	if (td_read(td))
		return 1;
	// For non-zrwa cases  and no dynamic qd option return 1
	if ((td->o.zone_mode == ZONE_MODE_NONE) || (!td->o.zrwa_alloc && !td->o.dynamic_qd))
		return 1;

	zone_idx = zbd_zone_idx(f, io_u->offset);
	z = &f->zbd_info->zone_info[zone_idx];

	if (!z->io_q_count)
		return 1;

	if ((io_u->offset + io_u->buflen -
		zbd_get_lowest_queued_offset(z, io_u->offset)) <= ZRWA_SIZE_BYTES)
		return 1;

	return 0;
}

/*
 * Open a ZBD zone if it was not yet open. Returns true if either the zone was
 * already open or if opening a new zone is allowed. Returns false if the zone
 * was not yet open and opening a new zone would cause the zone limit to be
 * exceeded.
 */
static bool zbd_open_zone(struct thread_data *td, const struct io_u *io_u,
			  uint32_t zone_idx)
{
	const uint32_t min_bs = td->o.min_bs[DDIR_WRITE];
	const struct fio_file *f = io_u->file;
	struct fio_zone_info *z = &f->zbd_info->zone_info[zone_idx];
	bool res = true;

	if (z->cond == ZBD_ZONE_COND_OFFLINE)
		return false;

	/*
	 * Skip full zones with data verification enabled because resetting a
	 * zone causes data loss and hence causes verification to fail.
	 */
	if (td->o.verify != VERIFY_NONE && zbd_zone_full(f, z, min_bs))
		return false;

	if (g_finish_zone)
		z->finish_pct = td->o.finish_zone_pct;

	/* Zero means no limit */
	if (!g_max_open_zones)
		return true;

	if (td_random(td) &&
		(td->o.num_open_zones >= td->o.max_open_zones))
		return false;

	pthread_mutex_lock(&f->zbd_info->mutex);

	if (is_zone_open(td, zone_idx))
		goto out;
	res = false;
	if (td->o.num_open_zones >= g_max_open_zones)
		goto out;
	// Issue an explicit open with ZRWAA bit set via io-passtrhu.
	if (td->o.zrwa_alloc) {
		if (z->cond == ZBD_ZONE_COND_EMPTY ||
				z->cond == ZBD_ZONE_COND_CLOSED) {
			if(!zbd_issue_exp_open_zrwa(f, zone_idx, z->start >> NVME_ZONE_LBA_SHIFT, td->o.ns_id))
				goto out;
			z->cond = ZBD_ZONE_COND_EXP_OPEN;
		}
	} else
		z->cond = ZBD_ZONE_COND_IMP_OPEN;
	td->o.open_zones[td->o.num_open_zones++] = zone_idx;
	g_open_zones++;
	dprint(FD_ZBD, "%s: opening zone %d, id = %d, open_zones = %d, total_open = %d%s \n",
			f->file_name, zone_idx, td->thread_number, td->o.num_open_zones, g_open_zones, td->o.zrwa_alloc ? " with ZRWA": "");
	z->open = 1;
	res = true;

out:
	pthread_mutex_unlock(&f->zbd_info->mutex);
	return res;
}

/* The caller must hold f->zbd_info->mutex */
static void zbd_close_zone(struct thread_data *td, const struct fio_file *f,
			   unsigned int open_zone_idx)
{
	uint32_t zone_idx;
	struct fio_zone_info *z;

	assert(open_zone_idx < td->o.num_open_zones);
	zone_idx = td->o.open_zones[open_zone_idx];
	z = &f->zbd_info->zone_info[zone_idx];
	if (z->pending_ios && td_write(td) &&
		!td_ioengine_flagged(td, FIO_SYNCIO))
		io_u_quiesce(td);
	if (g_max_open_zones && td->o.issue_zone_finish &&
			(td->o.zrwa_alloc || (td->o.finish_zone_pct < 100))) {
		// Handle the case where fio is started and all zones in the range
		// are in full state. fio MO is to select a zone, open it, if it is
		// full then close it (this func), select next zone and open it and
		// send it to zbd_adjust_block(), which then checks if the zone is
		// full and if so resets the zone, and starts writing to it. In case
		// where all zones are full at start and issue_zone_finish is enabled
		// fio cannot close a zone properly as zone finish is done in the
		// IO completion path and IOs have not started in this case, so fio
		// cannot close the zone here in this func and num_open_zones is not
		// decremented so it cannot open a new zone.
		if ((z->cond == ZBD_ZONE_COND_FULL) && z->open) {
			goto close;
		}

		return;
	}
close:

	/* check if zone was already closed */
	if ((td->o.open_zones[open_zone_idx] == zone_idx) && (td->o.num_open_zones > 0)){

		dprint(FD_ZBD, "%s(%s): closing zone %d\n", __func__, f->file_name,
		   zone_idx);

		memmove(td->o.open_zones + open_zone_idx,
			td->o.open_zones + open_zone_idx + 1,
			(ZBD_MAX_OPEN_ZONES - (open_zone_idx + 1)) *
			sizeof(td->o.open_zones[0]));
		td->o.num_open_zones--;
		g_open_zones--;
		f->zbd_info->zone_info[zone_idx].open = 0;
		z->cond = ZBD_ZONE_COND_FULL;
	}

	return;
}

/* Anything goes as long as it is not a constant. */
static uint32_t pick_random_zone_idx(const struct fio_file *f,
				     const struct io_u *io_u, int open_zones)
{
	return io_u->offset * open_zones / f->real_file_size;
}

/*
 * Modify the offset of an I/O unit that does not refer to an open zone such
 * that it refers to an open zone. Close an open zone and open a new zone if
 * necessary. This algorithm can only work correctly if all write pointers are
 * a multiple of the fio block size. The caller must neither hold z->mutex
 * nor f->zbd_info->mutex. Returns with z->mutex held upon success.
 */
static struct fio_zone_info *zbd_convert_to_open_zone(struct thread_data *td,
						      struct io_u *io_u)
{
	const uint32_t min_bs = td->o.min_bs[io_u->ddir];
	const struct fio_file *f = io_u->file;
	struct fio_zone_info *z;
	unsigned int open_zone_idx = -1;
	unsigned int full_zone_idx = 0xFFFF;
	uint32_t zone_idx, new_zone_idx;
	int i = 0, open_count;
	bool find_random = (td_random(td) && td->o.perc_rand[DDIR_WRITE] > 0);

	assert(is_valid_offset(f, io_u->offset));

	if (g_max_open_zones) {
		zone_idx = td->o.open_zones[pick_random_zone_idx(f, io_u, td->o.num_open_zones)];
	} else {
		zone_idx = zbd_zone_idx(f, io_u->offset);
	}
	dprint(FD_ZBD, "%s(%s): starting from zone %d id = %d, zones = %d (offset 0x%llX, buflen %lld)\n",
	       __func__, f->file_name, zone_idx, td->thread_number, td->o.num_open_zones, io_u->offset, io_u->buflen);

	/*
	 * Since z->mutex is the outer lock and f->zbd_info->mutex the inner
	 * lock it can happen that the state of the zone with index zone_idx
	 * has changed after 'z' has been assigned and before f->zbd_info->mutex
	 * has been obtained. Hence the loop.
	 */
	for (;;) {
		uint32_t tmp_idx;

		z = &f->zbd_info->zone_info[zone_idx];

		if (pthread_mutex_trylock(&z->mutex) != 0) {
			if (!td_ioengine_flagged(td, FIO_SYNCIO))
				io_u_quiesce(td);
			pthread_mutex_lock(&z->mutex);
		}
		pthread_mutex_lock(&f->zbd_info->mutex);
		if (g_max_open_zones == 0)
			goto examine_zone;
		if (td->o.num_open_zones == 0) {
			pthread_mutex_unlock(&f->zbd_info->mutex);
			pthread_mutex_unlock(&z->mutex);
			dprint(FD_ZBD, "%s(%s): no zones are open\n",
			       __func__, f->file_name);
			goto open_zone;
		}
		open_zone_idx = ((io_u->offset - f->file_offset) *
			td->o.num_open_zones) / (f->io_size);
		assert(open_zone_idx < td->o.num_open_zones);
		new_zone_idx = td->o.open_zones[open_zone_idx];
		/*
		 * Start with quasi-random candidate zone.
		 */
		open_zone_idx = pick_random_zone_idx(f, io_u, td->o.num_open_zones);
		assert(open_zone_idx < td->o.num_open_zones);
		tmp_idx = open_zone_idx;
		for (i = 0; i < td->o.num_open_zones; i++) {
			uint32_t tmpz;

			if (tmp_idx >= td->o.num_open_zones)
				tmp_idx = 0;
			tmpz = td->o.open_zones[tmp_idx];

			if (is_valid_offset(f, f->zbd_info->zone_info[tmpz].start)) {
				open_zone_idx = tmp_idx;
				goto found_candidate_zone;
			}

			tmp_idx++;
		}
		dprint(FD_ZBD, "%s(%s): no candidate zone\n",
			__func__, f->file_name);
		pthread_mutex_unlock(&f->zbd_info->mutex);
		pthread_mutex_unlock(&z->mutex);
		return NULL;

found_candidate_zone:

		if (new_zone_idx == zone_idx)
			break;
		zone_idx = new_zone_idx;
		pthread_mutex_unlock(&f->zbd_info->mutex);
		pthread_mutex_unlock(&z->mutex);
	}

	/* Both z->mutex and f->zbd_info->mutex are held. */

examine_zone:
if ((z->wp + min_bs <= z->start + z->capacity) &&
		(z->last_io != ZONE_LAST_IO_QUEUED)	&&
		is_valid_offset(f, z->start) &&
		(z->cond != ZBD_ZONE_COND_FULL)) {
		pthread_mutex_unlock(&f->zbd_info->mutex);
		goto out;
	}

	if (g_max_open_zones) {
		zbd_close_zone(td, f, open_zone_idx);
		/* Cover case where max zones are open and one is closed here but device
		 * has not marked zone as full.  This causes io errors if io is
		 * started on a new zone too soon.  Get number of open zones from device
		 * until less than max open zones
		 */
		if ((g_open_zones >= g_mar) && !td->o.issue_zone_finish) {
			open_count = zbd_get_open_count(f->fd, g_nsid);
			dprint(FD_ZBD, "%s(%s): zone %d id = %d, open zones = %d\n",
			      __func__, f->file_name, zone_idx, td->thread_number, open_count);
			while ((open_count > g_mar) && i < 150) {
				io_u_quiesce(td);
				usec_sleep(td,10);
				open_count = zbd_get_open_count(f->fd, g_nsid);
				i++;
			}
			assert(g_open_zones <= g_mar);
			dprint(FD_ZBD, "%s(%s): zone %d id = %d, open zones = %d, i = %d\n",
			      __func__, f->file_name, zone_idx, td->thread_number, open_count, i);
		}
	}
	pthread_mutex_unlock(&f->zbd_info->mutex);
    if (!td->o.issue_zone_finish) {
    	z->cond = ZBD_ZONE_COND_FULL;
    }

    /* Only z->mutex is held. */

	/* Zone 'z' is full, so try to open a new zone. */
open_zone:

    if ((g_max_open_zones > 0) && (td->o.num_open_zones < td->o.max_open_zones)) {

		srand(time(NULL));
		for (i = f->io_size / f->zbd_info->zone_size; i > 0; i--) {
			zone_idx++;
			pthread_mutex_unlock(&z->mutex);
			if (find_random) {
				zone_idx = rand() % (uint32_t)(f->io_size / f->zbd_info->zone_size);
				z = &f->zbd_info->zone_info[zone_idx];
				if ((z->cond == ZBD_ZONE_COND_FULL) && (full_zone_idx == 0xFFFF)) full_zone_idx = zone_idx;
			} else {
				z++;
			}
			if (!is_valid_offset(f, z->start)) {
				/* Wrap-around. */
				zone_idx = zbd_zone_idx(f, f->file_offset);
				z = &f->zbd_info->zone_info[zone_idx];
			}
			assert(is_valid_offset(f, z->start));
			/* if last iteration and have not found not open or non-full zone then try to find one sequentially */
			if (find_random && (i==1) && (z->open || (z->cond == ZBD_ZONE_COND_FULL))) {
				/* Wrap-around. */
				zone_idx = zbd_zone_idx(f, f->file_offset);
				z = &f->zbd_info->zone_info[zone_idx];
				find_random = false;
				i = f->io_size / f->zbd_info->zone_size;
			}
			pthread_mutex_lock(&z->mutex);
			if ((z->open) || (z->cond == ZBD_ZONE_COND_FULL))
				continue;
			if (zbd_open_zone(td, io_u, zone_idx))
				goto out;
		}
    }

	/* Check whether the write fits in any of the already opened zones. */
	pthread_mutex_lock(&f->zbd_info->mutex);
	for (i = 0; i < td->o.num_open_zones; i++) {
		zone_idx = td->o.open_zones[i];
		open_zone_idx = i;
		pthread_mutex_unlock(&f->zbd_info->mutex);
		pthread_mutex_unlock(&z->mutex);

		z = &f->zbd_info->zone_info[zone_idx];

		pthread_mutex_lock(&z->mutex);
		if ((z->wp + min_bs <= z->start + z->capacity) &&
				is_valid_offset(f, z->start) && (z->cond != ZBD_ZONE_COND_FULL)) {
			goto out;
		}
		pthread_mutex_lock(&f->zbd_info->mutex);
	}
	pthread_mutex_unlock(&f->zbd_info->mutex);
	pthread_mutex_unlock(&z->mutex);
	dprint(FD_ZBD, "%s(%s): did not open another zone, id = %d, zone = %d, zone_idx = %d\n", __func__,
	       f->file_name, td->thread_number, zone_idx, i);
	return NULL;

out:
	dprint(FD_ZBD, "%s(%s): returning zone %d, offset = 0x%lX\n", __func__, f->file_name,
	       zone_idx, z->start);
	io_u->offset = z->start;
	return z;
}

/* The caller must hold z->mutex. */
static struct fio_zone_info *zbd_replay_write_order(struct thread_data *td,
						    struct io_u *io_u,
						    struct fio_zone_info *z)
{
	const struct fio_file *f = io_u->file;
	const uint32_t min_bs = td->o.min_bs[DDIR_WRITE];

	if (!zbd_open_zone(td, io_u, z - f->zbd_info->zone_info)) {
		pthread_mutex_unlock(&z->mutex);
		z = zbd_convert_to_open_zone(td, io_u);
		assert(z);
	}

	if (z->verify_block * min_bs > z->capacity)
		log_err("%s: %d * %d >= %llu\n", f->file_name, z->verify_block,
			min_bs, (unsigned long long) f->zbd_info->zone_size);
	io_u->offset = z->start + z->verify_block++ * min_bs;
	return z;
}

/*
 * Find another zone for which @io_u fits below the write pointer. Start
 * searching in zones @zb + 1 .. @zl and continue searching in zones
 * @zf .. @zb - 1.
 *
 * Either returns NULL or returns a zone pointer and holds the mutex for that
 * zone.
 */
static struct fio_zone_info *
zbd_find_zone(struct thread_data *td, struct io_u *io_u,
	      struct fio_zone_info *zb, struct fio_zone_info *zl)
{
	const uint32_t min_bs = td->o.min_bs[io_u->ddir];
	const struct fio_file *f = io_u->file;
	struct fio_zone_info *z1, *z2;
	const struct fio_zone_info *const zf =
		&f->zbd_info->zone_info[zbd_zone_idx(f, f->file_offset)];

	/*
	 * Skip to the next non-empty zone in case of sequential I/O and to
	 * the nearest non-empty zone in case of random I/O.
	 */
	for (z1 = zb + 1, z2 = zb - 1; z1 < zl || z2 >= zf; z1++, z2--) {
		if (z1 < zl && z1->cond != ZBD_ZONE_COND_OFFLINE) {
			pthread_mutex_lock(&z1->mutex);
			if (z1->start + min_bs <= z1->wp)
				return z1;
			pthread_mutex_unlock(&z1->mutex);
		} else if (!td_random(td)) {
			break;
		}
		if (td_random(td) && z2 >= zf &&
		    z2->cond != ZBD_ZONE_COND_OFFLINE) {
			pthread_mutex_lock(&z2->mutex);
			if (z2->start + min_bs <= z2->wp)
				return z2;
			pthread_mutex_unlock(&z2->mutex);
		}
	}
	dprint(FD_ZBD, "%s: adjusting random read offset failed\n",
	       f->file_name);
	return NULL;
}

int zbd_finish_full_zone(struct thread_data *td, struct fio_zone_info *z,
			const struct io_u *io_u, bool zone_io_finish)
{
    int i, ret = 0, open_zone_idx = -1;
    struct fio_file *f = io_u->file;
    uint32_t zone_idx;

    zone_idx = zbd_zone_idx(f, io_u->offset);
    if (g_finish_zone && zone_io_finish) {
		dprint(FD_ZBD, "%s(%s): Issuing BLKFINISHZONE on zone %d\n", __func__,
				f->file_name, zone_idx);
		ret = zbd_issue_finish(td, f, z->start, f->zbd_info->zone_size);
		if (ret < 0)
			perror("Issuing finish failed with: ");
		if (g_ow)
			z->ow_count = 0;

		z->cond = ZBD_ZONE_COND_FULL;
		z->last_io = 0;
		z->io_q_count = 0;

		for (i = 0; i < td->o.num_open_zones; i++)
			if (td->o.open_zones[i] == zone_idx)
				open_zone_idx = i;

		/* check if zone was already closed */
		if (open_zone_idx != -1) {

			assert(open_zone_idx < td->o.num_open_zones);

			memmove(td->o.open_zones + open_zone_idx,
				td->o.open_zones + open_zone_idx + 1,
				(ZBD_MAX_OPEN_ZONES - (open_zone_idx + 1)) *
				sizeof(td->o.open_zones[0]));
			td->o.num_open_zones--;
			g_open_zones--;
			f->zbd_info->zone_info[zone_idx].open = 0;
		}
    }
    return ret;
}

/**
 * zbd_queue_io - update the write pointer of a sequential zone
 * @io_u: I/O unit
 * @success: Whether or not the I/O unit has been queued successfully
 * @q: queueing status (busy, completed or queued).
 *
 * For write and trim operations, update the write pointer of the I/O unit
 * target zone.
 */
static void zbd_queue_io(struct thread_data *td,
		struct io_u *io_u, int q, bool success)
{
	const struct fio_file *f = io_u->file;
	struct zoned_block_device_info *zbd_info = f->zbd_info;
	struct fio_zone_info *z;
	uint32_t zone_idx;
	uint64_t zone_end;

	if (!zbd_info)
		return;

	zone_idx = zbd_zone_idx(f, io_u->offset);
	assert(zone_idx < zbd_info->nr_zones);
	z = &zbd_info->zone_info[zone_idx];

	if (!zbd_zone_swr(z))
		return;

	if (!success)
		goto unlock;

	if (td->o.zrwa_alloc && td->o.dynamic_qd && (io_u->ddir == DDIR_WRITE)) {
		assert(z->io_q_count < td->o.iodepth + 1);
		z->zone_io_q[z->io_q_count++] = io_u->offset;
	}

	dprint(FD_ZBD, "%s: queued I/O (%lld, %llu) for zone %u, q-len = %u\n",
		f->file_name, io_u->offset, io_u->buflen, zone_idx, z->io_q_count);

	switch (io_u->ddir) {
	case DDIR_WRITE:
		z->pending_ios++;
		zone_end = min((uint64_t)(io_u->offset + io_u->buflen),
			       (z->start + z->capacity));

		if (z->start + z->capacity == io_u->offset + io_u->buflen)
			z->last_io = ZONE_LAST_IO_QUEUED;

		pthread_mutex_lock(&zbd_info->mutex);
		/*
		 * z->wp > zone_end means that one or more I/O errors
		 * have occurred.
		 */
		if (z->wp <= zone_end)
			zbd_info->sectors_with_data += zone_end - z->wp;
		pthread_mutex_unlock(&zbd_info->mutex);
		z->wp = zone_end;
		break;
	case DDIR_TRIM:
		assert(z->wp == z->start);
		break;
	default:
		break;
	}

unlock:
	if (!success || q != FIO_Q_QUEUED) {
		/* BUSY or COMPLETED: unlock the zone */
		if(td_ioengine_flagged(td, FIO_SYNCIO)) {
			if (z->start + z->capacity == io_u->offset + io_u->buflen
					&& (io_u->ddir != DDIR_READ))
				zbd_finish_full_zone(td, z, io_u, true);
		}
		/* If BUSY, keep the lock and the zbd_put_io cb,
		 * so that we can get the completion
		 */
		if (q == FIO_Q_BUSY) {
			assert(success);
		} else {
			pthread_mutex_unlock(&z->mutex);
			io_u->zbd_put_io = NULL;
		}
	}
}

unsigned int zbd_get_zone_q_io_idx(struct fio_zone_info *z, uint64_t offset)
{
	int i;

	for (i = 0; i < z->io_q_count; i++) {
		if (offset == z->zone_io_q[i])
			return i;
	}
	printf("%s: Error: Did not find the completed io at offset %ld in the zone io queue\n", __func__, offset);
	assert(0);
	return 0;
}
/**
 * zbd_put_io - Unlock an I/O unit target zone lock
 * @io_u: I/O unit
 */
static void zbd_put_io(struct thread_data *td, const struct io_u *io_u)
{
	const struct fio_file *f = io_u->file;
	struct zoned_block_device_info *zbd_info = f->zbd_info;

	struct fio_zone_info *z;
	uint32_t zone_idx, zone_q_io_idx;
    uint64_t finish_limit = 0;

	if (!zbd_info)
		return;

	zone_idx = zbd_zone_idx(f, io_u->offset);
	assert(zone_idx < zbd_info->nr_zones);
	z = &zbd_info->zone_info[zone_idx];

	if (!zbd_zone_swr(z))
		return;

 	if (io_u->ddir == DDIR_WRITE) {
		assert(z->pending_ios);
		z->pending_ios--;
	}

	dprint(FD_ZBD, "%s: terminate I/O (%lld, %llu) for zone %u\n",
		f->file_name, io_u->offset, io_u->buflen, zone_idx);

	if (td->o.zrwa_alloc && td->o.dynamic_qd && (io_u->ddir == DDIR_WRITE)) {
		if (!z->io_q_count) {
			printf("%s: Error: zone io queue is empty !! offset %lld \n", __func__, io_u->offset);
			assert(0);
		}
		for (int i = 0; i < z->io_q_count; i++)
			dprint(FD_ZBD, "z->zone_io_q[%d] = %lu \n", i, z->zone_io_q[i]);

		zone_q_io_idx = zbd_get_zone_q_io_idx(z, io_u->offset);
		if (zone_q_io_idx + 1 == z->io_q_count) {
			z->io_q_count--;
			z->zone_io_q[zone_q_io_idx] = 0;
		} else {
			memmove(z->zone_io_q + zone_q_io_idx,
				z->zone_io_q + zone_q_io_idx + 1,
				(z->io_q_count - (zone_q_io_idx + 1)) * sizeof(uint64_t));
			z->io_q_count--;
		}
	}

        // If bs < commit_gran, if completed IO address is a multiple of commit gran,
        // then issue a commit to that lba.
        // If bs >= commit_gran, ex: bs=64K, commmit_gran = 16K, then issue 64/16= 4 commit
        // commands.

	if (g_exp_commit) {
	    if (io_u->buflen < g_commit_gran) {
		    if ((io_u->offset + io_u->buflen) >= g_commit_gran &&
			    !((io_u->offset + io_u->buflen) % g_commit_gran)) {
		    if(!zbd_issue_commit_zone(f, zone_idx,
		    		(((io_u->offset + io_u->buflen) >> NVME_ZONE_LBA_SHIFT) - 1),
		    		(z->start >> NVME_ZONE_LBA_SHIFT), td->o.ns_id))
			    dprint(FD_ZBD, "commit zone failed on zone %d, at offset %llu\n",
							    zone_idx, io_u->offset + io_u->buflen);
		    }
	    } else {
		    //In case io_u->buflen >= g_commit_gran
		    if(!zbd_issue_commit_zone(f, zone_idx,
		    		(((io_u->offset + io_u->buflen) >> NVME_ZONE_LBA_SHIFT) - 1),
		    		z->start >> NVME_ZONE_LBA_SHIFT, td->o.ns_id))
			    dprint(FD_ZBD, "commit zone failed on zone %d, at offset %llu\n",
				    zone_idx, io_u->offset + io_u->buflen);
	    }
	}

	if (z->finish_pct == 0)
	{
		finish_limit = z->capacity;
	} else {
		finish_limit = (z->capacity * z->finish_pct) / 100;
	}
	if (((io_u->offset + io_u->buflen) >= (z->start + finish_limit)) &&
			((io_u->offset + io_u->buflen) <= (z->start + z->capacity))) {
		z->last_io = ZONE_LAST_IO_COMPLETED;
	}
	if (!z->io_q_count && z->last_io == ZONE_LAST_IO_COMPLETED &&
							(io_u->ddir == DDIR_WRITE))
		zbd_finish_full_zone(td, z, io_u, true);

	assert(pthread_mutex_unlock(&z->mutex) == 0);
	zbd_check_swd(f);
}

/*
 * Windows and MacOS do not define this.
 */
#ifndef EREMOTEIO
#define EREMOTEIO	121	/* POSIX value */
#endif

bool zbd_unaligned_write(int error_code)
{
	switch (error_code) {
	case EIO:
	case EREMOTEIO:
		return true;
	}
	return false;
}

/**
 * setup_zbd_zone_mode - handle zoneskip as necessary for ZBD drives
 * @td: FIO thread data.
 * @io_u: FIO I/O unit.
 *
 * For sequential workloads, change the file offset to skip zoneskip bytes when
 * no more IO can be performed in the current zone.
 * - For read workloads, zoneskip is applied when the io has reached the end of
 *   the zone or the zone write position (when td->o.read_beyond_wp is false).
 * - For write workloads, zoneskip is applied when the zone is full.
 * This applies only to read and write operations.
 */
void setup_zbd_zone_mode(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	enum fio_ddir ddir = io_u->ddir;
	struct fio_zone_info *z;
	uint32_t zone_idx;

	assert(td->o.zone_mode == ZONE_MODE_ZBD);
	assert(td->o.zone_size);

	/*
	 * zone_skip is valid only for sequential workloads.
	 */
	if (td_random(td) || !td->o.zone_skip)
		return;

	/*
	 * It is time to switch to a new zone if:
	 * - zone_bytes == zone_size bytes have already been accessed
	 * - The last position reached the end of the current zone.
	 * - For reads with td->o.read_beyond_wp == false, the last position
	 *   reached the zone write pointer.
	 */
	zone_idx = zbd_zone_idx(f, f->last_pos[ddir]);
	z = &f->zbd_info->zone_info[zone_idx];

	if (td->zone_bytes >= td->o.zone_size ||
	    f->last_pos[ddir] >= (z+1)->start ||
	    (ddir == DDIR_READ &&
	     (!td->o.read_beyond_wp) && f->last_pos[ddir] >= z->wp)) {
		/*
		 * Skip zones.
		 */
		td->zone_bytes = 0;
		f->file_offset += td->o.zone_size + td->o.zone_skip;

		/*
		 * Wrap from the beginning, if we exceed the file size
		 */
		if (f->file_offset >= f->real_file_size)
			f->file_offset = get_start_offset(td, f);

		f->last_pos[ddir] = f->file_offset;
		td->io_skip_bytes += td->o.zone_skip;
	}
}

/**
 * zbd_adjust_ddir - Adjust an I/O direction for zonemode=zbd.
 *
 * @td: FIO thread data.
 * @io_u: FIO I/O unit.
 * @ddir: I/O direction before adjustment.
 *
 * Return adjusted I/O direction.
 */
enum fio_ddir zbd_adjust_ddir(struct thread_data *td, struct io_u *io_u,
						enum fio_ddir ddir)
{
	/*
	 * In case read direction is chosen for the first random I/O, fio with
	 * zonemode=zbd stops because no data can be read from zoned block
	 * devices with all empty zones. Overwrite the first I/O direction as
	 * write to make sure data to read exists.
	 */
	if (ddir != DDIR_READ || !td_rw(td))
		return ddir;

	if (io_u->file->zbd_info->sectors_with_data ||
		td->o.read_beyond_wp)
		return DDIR_READ;

	return DDIR_WRITE;
}

/**
 * zbd_adjust_block - adjust the offset and length as necessary for ZBD drives
 * @td: FIO thread data.
 * @io_u: FIO I/O unit.
 *
 * Locking strategy: returns with z->mutex locked if and only if z refers
 * to a sequential zone and if io_u_accept is returned. z is the zone that
 * corresponds to io_u->offset at the end of this function.
 */
enum io_u_action zbd_adjust_block(struct thread_data *td, struct io_u *io_u)
{
	const struct fio_file *f = io_u->file;
	uint32_t zone_idx_b;
	struct fio_zone_info *zb, *zl, *orig_zb;
	uint32_t orig_len = io_u->buflen;
	uint32_t min_bs = td->o.min_bs[io_u->ddir];
	uint64_t new_len;
	int64_t range;

	if (!f->zbd_info)
		return io_u_accept;

	assert(min_bs);
	assert(is_valid_offset(f, io_u->offset));
	assert(io_u->buflen);
	zone_idx_b = zbd_zone_idx(f, io_u->offset);
	zb = &f->zbd_info->zone_info[zone_idx_b];
	orig_zb = zb;

	/* Accept the I/O offset for conventional zones. */
	if (!zbd_zone_swr(zb))
		return io_u_accept;

	/*
	 * Accept the I/O offset for reads if reading beyond the write pointer
	 * is enabled.
	 */
	if (zb->cond != ZBD_ZONE_COND_OFFLINE &&
	    io_u->ddir == DDIR_READ && td->o.read_beyond_wp) {
		if (io_u->offset + io_u->buflen <= zb->start + zb->capacity)
			return io_u_accept;
	}

	zbd_check_swd(f);

	/*
	 * Lock the io_u target zone. The zone will be unlocked if io_u offset
	 * is changed or when io_u completes and zbd_put_io() executed.
	 * To avoid multiple jobs doing asynchronous I/Os from deadlocking each
	 * other waiting for zone locks when building an io_u batch, first
	 * only trylock the zone. If the zone is already locked by another job,
	 * process the currently queued I/Os so that I/O progress is made and
	 * zones unlocked.
	 */
	if (pthread_mutex_trylock(&zb->mutex) != 0) {
		if (!td_ioengine_flagged(td, FIO_SYNCIO))
			io_u_quiesce(td);
		pthread_mutex_lock(&zb->mutex);
	}

	switch (io_u->ddir) {
	case DDIR_READ:
		if (td->runstate == TD_VERIFYING) {
			if (td_write(td)) {
				zb = zbd_replay_write_order(td, io_u, zb);
				goto accept;
			}
		}
		/*
		 * Check that there is enough written data in the zone to do an
		 * I/O of at least min_bs B. If there isn't, find a new zone for
		 * the I/O.
		 */
		range = zb->cond != ZBD_ZONE_COND_OFFLINE ?
			zb->wp - zb->start : 0;
		if (range < min_bs ||
		    ((!td_random(td)) && (io_u->offset + min_bs > zb->wp))) {
			pthread_mutex_unlock(&zb->mutex);
			zl = &f->zbd_info->zone_info[zbd_zone_idx(f,
						f->file_offset + f->io_size)];
			zb = zbd_find_zone(td, io_u, zb, zl);
			if (!zb) {
				dprint(FD_ZBD,
				       "%s: zbd_find_zone(%lld, %llu) failed\n",
				       f->file_name, io_u->offset,
				       io_u->buflen);
				goto eof;
			}
			/*
			 * zbd_find_zone() returned a zone with a range of at
			 * least min_bs.
			 */
			range = zb->wp - zb->start;
			assert(range >= min_bs);

			if (!td_random(td))
				io_u->offset = zb->start;
		}
		/*
		 * Make sure the I/O is within the zone valid data range while
		 * maximizing the I/O size and preserving randomness.
		 */
		if (range <= io_u->buflen)
			io_u->offset = zb->start;
		else if (td_random(td))
			io_u->offset = zb->start +
				((io_u->offset - orig_zb->start) %
				 (range - io_u->buflen)) / min_bs * min_bs;
		/*
		 * Make sure the I/O does not cross over the zone wp position.
		 */
		new_len = min((unsigned long long)io_u->buflen,
			      (unsigned long long)(zb->wp - io_u->offset));
		new_len = new_len / min_bs * min_bs;
		if (new_len < io_u->buflen) {
			io_u->buflen = new_len;
			dprint(FD_IO, "Changed length from %u into %llu\n",
			       orig_len, io_u->buflen);
		}
		assert(zb->start <= io_u->offset);
		assert(io_u->offset + io_u->buflen <= zb->wp);
		goto accept;
	case DDIR_WRITE:
		if (io_u->buflen > f->zbd_info->zone_size)
			goto eof;
		if (!zbd_open_zone(td, io_u, zone_idx_b)) {
			pthread_mutex_unlock(&zb->mutex);
			zb = zbd_convert_to_open_zone(td, io_u);
			if (!zb) {
				/*
				 * If time based and sequential write then
				 * reset zone if cannot open a new zone
				 */
				if ((td->o.time_based) && !td_random(td))
				{
					zb = orig_zb;
					zb->reset_zone = 1;
				} else {
					goto eof;
				}
			}
			zone_idx_b = zb - f->zbd_info->zone_info;
		}
		/* Check whether the zone reset threshold has been exceeded */
		if (td->o.zrf.u.f) {
			if (f->zbd_info->sectors_with_data >=
			    f->io_size * td->o.zrt.u.f &&
			    zbd_dec_and_reset_write_cnt(td, f)) {
				zb->reset_zone = 1;
			}
		}

		if ((!td_random(td) || td->o.perc_rand[DDIR_WRITE] == 0) &&
				f->zbd_info->zone_size > zb->capacity) {
			/*
			 * Seq write on a dev with zone capacity < zone size,
			 * when wp is at zone capacity, explicitly go to
			 * next available zone to contiue seq write
			 */
			if (zbd_zone_full(f, zb, min_bs)) {
				pthread_mutex_unlock(&zb->mutex);
				zb = zbd_convert_to_open_zone(td, io_u);
				if (!zb) {
					/*
					 * If sequential write then
					 * if cannot open a new zone then pick next zone
					 * if last zone then wrap around
					 */
					if (!td_random(td) || td->o.perc_rand[DDIR_WRITE] == 0) {
						zone_idx_b++;
						if (zone_idx_b >= f->zbd_info->nr_zones)
							zone_idx_b = 0;
						zb = &f->zbd_info->zone_info[zone_idx_b];
						pthread_mutex_lock(&zb->mutex);
					} else {
						goto eof;
					}
				}
			}
        }

		/* Reset the zone pointer if necessary */
		/*
		 * Since previous write requests may have been submitted
		 * asynchronously and since we will submit the zone
		 * reset synchronously, wait until previously submitted
		 * write requests have completed before issuing a
		 * zone reset.
		 */
		if (zb->reset_zone || zbd_zone_full(f, zb, min_bs)) {
			assert(td->o.verify == VERIFY_NONE);
			/* If filling empty zones first attempt to open an empty zone rather
			 * than reset current zone*/
			if ((td->o.fill_empty_zones_first) && zbd_zone_full(f, zb, min_bs)) {
				if (full_zones(f) <= (f->zbd_info->nr_zones - g_max_open_zones)) {
					pthread_mutex_unlock(&zb->mutex);
					zb = zbd_convert_to_open_zone(td, io_u);
					if (!zb)
						goto eof;
					else if (zbd_zone_full(f, zb, min_bs)) {
						zb->reset_zone = true;
					}
				} else {
					zb->reset_zone = true;
				}
			} else {
				zb->reset_zone = true;
			}
		}

		if (zb->reset_zone) {
			io_u_quiesce(td);
			zb->reset_zone = 0;
			if (zbd_reset_zone(td, f, zb) < 0)
				goto eof;
			if (td->o.zrwa_alloc) {
				if(!zbd_issue_exp_open_zrwa(f,
				zbd_zone_idx(f, zb->start), (zb->start >> NVME_ZONE_LBA_SHIFT), td->o.ns_id))
					return -1;
				zb->cond = ZBD_ZONE_COND_EXP_OPEN;
			}
		}
		/* Make writes occur at the write pointer */
		assert(!zbd_zone_full(f, zb, min_bs));
		io_u->offset = zb->wp;

		// If overwrites are set, then issue a write to previously
		// written location, which is wp - buflen, ensure the offset
		// is greater zone start + buflen, so that the IO are not
		// sent to previous zone.
		if (td->o.zrwa_overwrite_percent && td->o.zrwa_alloc) {
		   // Issue write to a zone until ow_count reaches td->zbd_ow_blk_count
		   // During finishing a zone, reset ow_count 0
		   if (zb->ow_count < td->zbd_ow_blk_count &&
				   (io_u->offset >= zb->start + io_u->buflen) &&
				   io_u->offset >= zb->dev_wp + io_u->buflen) {
			   if (td->o.zrwa_rand_ow) {
				   srand(time(NULL));
				   if (!(rand() % td->o.zrwa_divisor)) {
					   if (zb->prev_ow_lba != (io_u->offset - io_u->buflen)) {
						   io_u->offset -= io_u->buflen;
						   zb->prev_ow_lba = io_u->offset;
						   zb->ow_count++;
						   td->ts.zrwa_overwrite_bytes += io_u->buflen;
					       dprint(FD_ZBD,"Issuing overwrite io to offset %llu\n",
										       io_u->offset);
					   }
				   }
			   } else {
				   // Issue overwrite uniformly after every x IOs.
				   // where x is total-blocks-in-zone / number-of-blks-to-be-overwritten
				   // track prev_ow_lba to avoid sendinf ow to same lba again
				   if (!(((io_u->offset - zb->start) / td->o.bs[1]) % td->zbd_ow_blk_interval)) {
					   if (zb->prev_ow_lba != (io_u->offset - io_u->buflen)) {
						   io_u->offset -= io_u->buflen;
						   td->ts.zrwa_overwrite_bytes += io_u->buflen;
						   zb->ow_count++;
						   zb->prev_ow_lba = io_u->offset;
					       dprint(FD_ZBD,"Issuing overwrite io at offset %llu, z->start= %lu, z->wp= %lu, ow_count = %d\n",
							       io_u->offset, zb->start, zb->wp, zb->ow_count);
					   }
				   }
				}
			}
		}

		if (!is_valid_offset(f, io_u->offset)) {
			dprint(FD_ZBD, "Dropped request with offset %llu\n",
			       io_u->offset);
			goto eof;
		}

		/*
		 * Make sure that the buflen is a multiple of the minimal
		 * block size. Give up if shrinking would make the request too
		 * small.
		 */
		new_len = min((unsigned long long)io_u->buflen,
			      ((zb->start + zb->capacity) - io_u->offset));
		new_len = new_len / min_bs * min_bs;
		if (new_len == io_u->buflen)
			goto accept;
		if (new_len >= min_bs) {
			io_u->buflen = new_len;
			dprint(FD_IO, "Changed length from %u into %llu\n",
			       orig_len, io_u->buflen);
			goto accept;
		}
		log_err("Zone remainder %lld smaller than minimum block size %d\n",
			((zb + 1)->start - io_u->offset),
			min_bs);
		goto eof;
	case DDIR_TRIM:
		/* fall-through */
	case DDIR_SYNC:
	case DDIR_DATASYNC:
	case DDIR_SYNC_FILE_RANGE:
	case DDIR_WAIT:
	case DDIR_LAST:
	case DDIR_INVAL:
		goto accept;
	}

	assert(false);

accept:
	assert(zb);
	assert(zb->cond != ZBD_ZONE_COND_OFFLINE);
	assert(!io_u->zbd_queue_io);
	assert(!io_u->zbd_put_io);
	io_u->zbd_queue_io = zbd_queue_io;
	io_u->zbd_put_io = zbd_put_io;
	return io_u_accept;

eof:
	if (zb)
		pthread_mutex_unlock(&zb->mutex);
	return io_u_eof;
}

/* Return a string with ZBD statistics */
char *zbd_write_status(const struct thread_stat *ts)
{
	char *res;
	char *cptr;

	if (asprintf(&cptr, ", %lu MB ZRWA Overwrites done",
				(unsigned long)ts->zrwa_overwrite_bytes / (1024 * 1024)) < 0)
		return NULL;

	if (asprintf(&res, "; %llu zone resets%s", (unsigned long long) ts->nr_zone_resets,
								g_ow ? cptr: "") < 0)
		return NULL;
	return res;
}
