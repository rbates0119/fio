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

#include "os/os.h"
#include "file.h"
#include "fio.h"
#include "lib/pow2.h"
#include "log.h"
#include "oslib/asprintf.h"
#include "smalloc.h"
#include "verify.h"
#include "pshared.h"
#include "zbd.h"

static int g_ow;
static unsigned int g_max_open_zones;
static unsigned int g_mar;
static unsigned int g_rand_seed = 0;

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
		/* If device is nvme then use zone management receive command to get zone info */
		if (strncmp("/dev/nvme", f->file_name, 9)) {
			ret = blkzoned_report_zones(td, f, offset, zones, nr_zones);
		} else {
			ret = zbd_zone_mgmt_report(td, f, offset, zones, nr_zones);
			if (ret < 0)
				ret = blkzoned_report_zones(td, f, offset, zones, nr_zones);
		}
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
int zbd_reset_wp(struct thread_data *td, struct fio_file *f,
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
 * zbd_zone_end - Return zone end location
 * @z: zone info pointer.
 */
static inline uint64_t zbd_zone_end(const struct fio_zone_info *z)
{
	return (z+1)->start;
}

/**
 * zbd_zone_capacity_end - Return zone capacity limit end location
 * @z: zone info pointer.
 */
static inline uint64_t zbd_zone_capacity_end(struct thread_data *td, const struct fio_zone_info *z)
{
	return z->start + td->zbd_finish_capacity;
}

/**
 * zbd_zone_full - verify whether a minimum number of bytes remain in a zone
 * @f: file pointer.
 * @z: zone info pointer.
 * @required: minimum number of bytes that must remain in a zone.
 *
 * The caller must hold z->mutex.
 */
static bool zbd_zone_full(struct thread_data *td, const struct fio_file *f,
		struct fio_zone_info *z, uint64_t required)
{
	assert((required & 511) == 0);
	return (zbd_zone_swr(z) &&
			((z->wp + required >= z->start + td->zbd_finish_capacity) || z->cond == ZBD_ZONE_COND_FULL));

}

static void zone_lock(struct thread_data *td, struct fio_file *f, struct fio_zone_info *z)
{
	struct zoned_block_device_info *zbd = f->zbd_info;
	uint32_t nz = z - zbd->zone_info;

	/* A thread should never lock zones outside its working area. */

	assert(f->min_zone <= nz && nz <= f->max_zone);

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
static bool zbd_verify_sizes(struct thread_data *td)
{
	const struct fio_zone_info *z;
	struct fio_file *f;
	uint64_t new_offset, new_end;
	uint32_t zone_idx;
	int i, j;
	unsigned long long cap_percent;

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
		if ((f->file_offset != z->start) &&
			(td->o.td_ddir != TD_DDIR_READ)) {
			new_offset = zbd_zone_end(z);
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

		if (!td_random(td) || td->o.perc_rand[DDIR_WRITE] == 0) {
			if (td->o.max_open_zones > 1) {
				log_info("%s: changed max_open_zones from %d to 1 for sequential workload, id = %d\n",
						f->file_name, td->o.max_open_zones, td->thread_number);
				td->o.max_open_zones = 1;
			}
		}
		if (td->o.num_zones > 0)
			zone_idx = zbd_zone_idx(f, f->file_offset + (td->o.num_zones * td->o.zone_size));
		else
			zone_idx = zbd_zone_idx(f, f->file_offset + f->io_size);
		z = &f->zbd_info->zone_info[zone_idx];
		new_end = z->start;
		if ((td->o.td_ddir != TD_DDIR_READ) &&
			(f->file_offset + f->io_size != new_end)) {
			if (new_end <= f->file_offset) {
				log_info("%s: io_size must be at least one zone\n",
					 f->file_name);
				return false;
			}
			if (td->o.num_zones == 0) {
				log_info("%s: rounded down io_size from 0x%llX to 0x%llX, id = %d\n",
						f->file_name, (unsigned long long) f->io_size,
						(unsigned long long) new_end - f->file_offset, td->thread_number);
				td->o.num_zones = (f->max_zone + 1 - f->min_zone);
			}
			f->io_size = new_end - f->file_offset;
		}

		f->min_zone = zbd_zone_idx(f, f->file_offset);
		f->max_zone = (zbd_zone_idx(f, f->file_offset + f->io_size) - 1);
		if (td->o.num_zones == 0) {
			td->o.num_zones = (f->max_zone + 1 - f->min_zone);
		}

		assert(f->min_zone <= f->max_zone);
		dprint(FD_ZBD, "zbd_verify_sizes: Job %d zones = %d to %d, file_offset = 0x%lX, io_size = 0x%lX\n",
			 td->thread_number, f->min_zone, f->max_zone, f->file_offset, f->io_size);
		dprint(FD_ZBD, "zbd_verify_sizes: offset = 0x%llX, size = 0x%llX, io_size = 0x%llX\n",
				td->o.start_offset, td->o.size, td->o.io_size);

		td->zbd_finish_capacity = f->zbd_info->zone_info[0].capacity;
		cap_percent = (f->zbd_info->zone_info[0].capacity * td->o.finish_zone_pct) / 100;
		td->zbd_finish_capacity = cap_percent & ~(td->o.bs[1] - 1);

		if (td->o.ddir_seq_add) {
			td->zbd_finish_capacity = (((cap_percent / (td->o.bs[1] + td->o.ddir_seq_add)) *
					(td->o.bs[1] + td->o.ddir_seq_add)) - td->o.ddir_seq_add);
		}
		dprint(FD_ZBD, "zbd_verify_sizes: zone finish capacity = 0x%lX, cap_percent = 0x%llX, id = %d, \n",
				td->zbd_finish_capacity, cap_percent, td->thread_number);

		if ((td->o.zone_mode==ZONE_MODE_ZBD) && (strcmp(td->o.filename, f->file_name) == 0))
			g_max_open_zones += td->o.max_open_zones;

		/* Remove any open zones outside of work area */

		if (td->o.num_open_zones > 0) {
			for (i = 0; i < td->o.num_open_zones; i++) {
				if ((td->o.open_zones[i] <  f->min_zone) ||
					(td->o.open_zones[i] > f->max_zone)) {
					dprint(FD_ZBD, "zbd_verify_sizes: Removing open zone %d, open_zones = %d, id = %d\n",
							td->o.open_zones[i], td->o.num_open_zones - 1, td->thread_number);
					memmove(td->o.open_zones + i,
						td->o.open_zones + i + 1,
						(ZBD_MAX_OPEN_ZONES - (i + 1)) *
						sizeof(td->o.open_zones[0]));
					td->o.num_open_zones--;
					td->num_open_zones--;
					i--;
				}
			}
		}

		dprint(FD_ZBD, "zbd_verify_sizes: id = %d, max_zones = %d, open_zones = %d, max_open = %d\n",
				td->thread_number, g_max_open_zones, td->o.num_open_zones, td->o.max_open_zones);
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
	if (td->o.bs[1] > td->o.commit_gran &&
			(td->o.bs[1] % td->o.commit_gran)) {
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
	uint64_t zone_capacity = td->o.zone_capacity;
	struct zoned_block_device_info *zbd_info = NULL;
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

	if (zone_capacity == 0)
		zone_capacity = zone_size;

	if (zone_capacity > zone_size) {
		log_err("%s: job parameter zonecapacity %llu is larger than zone size %llu\n",
			f->file_name, (unsigned long long) td->o.zone_capacity,
			(unsigned long long) td->o.zone_size);
		return 1;
	}

	nr_zones = (f->real_file_size + zone_size - 1) / zone_size;
	zbd_info = scalloc(1, sizeof(*zbd_info) +
			   (nr_zones + 1) * sizeof(zbd_info->zone_info[0]));
	if (!zbd_info)
		return -ENOMEM;

	mutex_init_pshared(&zbd_info->mutex);
	zbd_info->refcount = 1;
	p = &zbd_info->zone_info[0];
	for (i = 0; i < nr_zones; i++, p++) {
		mutex_init_pshared_with_type(&p->mutex,
					     PTHREAD_MUTEX_RECURSIVE);
		p->start = i * zone_size;
		p->wp = p->start;
		p->type = ZBD_ZONE_TYPE_SWR;
		p->cond = ZBD_ZONE_COND_EMPTY;
		p->capacity = zone_capacity;
	}
	/* a sentinel */
	p->start = nr_zones * zone_size;

	f->zbd_info = zbd_info;
	f->zbd_info->zone_size = zone_size;
	f->zbd_info->zone_size_log2 = is_power_of_2(zone_size) ?
		ilog2(zone_size) : 0;
	f->zbd_info->nr_zones = nr_zones;
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
	int i, j, ns_id, bs, ret = 0;
	void *zone_q_buf = NULL;
	struct nvme_id_ns_zns_2 *ns_zns = NULL;
	struct nvme_id_ns *ns = NULL;
	char scheduler[15];
	struct thread_data *td2;
	uint32_t zrwas, zone_io_q_size = 0;
	bool set_cond = true;

	zones = calloc(ZBD_REPORT_MAX_ZONES, sizeof(struct zbd_zone));
	if (!zones)
		goto out;
	ns_zns = calloc(1,4096);
	if (!ns_zns)
		goto out;
	ns = calloc(1,4096);
	if (!ns)
		goto out;

	i=0;
	ns_id = zbd_get_nsid(f);

	for_each_td(td2, i) {

		if (td2->o.ns_id > 0) {
			if (ns_id > 0)
			{
				if ((ns_id != td2->o.ns_id) && (strcmp(td2->o.filename, f->file_name) == 0)) {
					log_err("fio: %s, %s, id = %d, job parameter ns_id = %u does not match device ns = %u.\n",
						f->file_name, td2->o.filename, td2->thread_number, td2->o.ns_id, ns_id);
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
	if ((td->o.ns_id == 0) && ns_id > 0)
		td->o.ns_id = ns_id;

	if (td->o.reset_all_zones_first) {
		if (!zbd_zone_reset(td, f, 0x00, true, td->o.ns_id))
			dprint(FD_ZBD, "parse_zone_info: reset zones failed \n");
		td->o.reset_all_zones_first = false;
	}
	zones[0].len = 0;
	nrz = zbd_report_zones(td, f, 0, zones, ZBD_REPORT_MAX_ZONES);
	if (nrz < 0) {
		ret = nrz;
		log_info("fio: report zones (offset 0) failed for %s (%d).\n",
			 f->file_name, -ret);
		goto out;
	}
	if (strncmp("/dev/nvme", f->file_name, 9))
		if (zones[0].len == 0)
			zone_size = zones[1].start - zones[0].start;
		else
			zone_size = zones[0].len;
	else
		zone_size = zones[1].start - zones[0].start;
	nr_zones = (f->real_file_size + zone_size - 1) / zone_size;
	if (nr_zones != nrz) {
		dprint(FD_ZBD, "parse_zone_info: num zones = %d, zone log header number of zones = %d\n",
				nr_zones, nrz);
		nr_zones = min(nr_zones, nrz);
	}
	if (td->o.zone_size == 0) {
		td->o.zone_size = zone_size;
	} else if (td->o.zone_size != zone_size) {
		log_err("fio: %s job parameter zonesize %llu does not match disk zone size %llu.\n",
			f->file_name, (unsigned long long) td->o.zone_size,
			(unsigned long long) zone_size);
		ret = -EINVAL;
		goto out;
	}

	dprint(FD_ZBD, "Device %s has %d zones of size 0x%llX\n", f->file_name,
	       nr_zones, (unsigned long long) zone_size);

	zbd_info = scalloc(1, sizeof(*zbd_info) +
			   (nr_zones + 1) * sizeof(zbd_info->zone_info[0]));
	ret = -ENOMEM;
	if (!zbd_info)
		goto out;
	mutex_init_pshared(&zbd_info->mutex);
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
			mutex_init_pshared_with_type(&p->mutex,
						     PTHREAD_MUTEX_RECURSIVE);
			p->start = z->start;
			p->capacity = z->capacity;
			if (td->o.zrwa_alloc && td->o.dynamic_qd && (td->o.td_ddir & TD_DDIR_WRITE)) {
				p->zone_io_q = zone_q_buf + (j * zone_io_q_size); // j is zone-idx
				p->last_io = 0;
			}

			switch (z->cond) {
			case ZBD_ZONE_COND_NOT_WP:
			case ZBD_ZONE_COND_FULL:
				p->wp = p->start + p->capacity;
				break;
			case ZBD_ZONE_COND_CLOSED:
			case ZBD_ZONE_COND_EXP_OPEN:
			case ZBD_ZONE_COND_IMP_OPEN:

				if (z->cond == ZBD_ZONE_COND_EXP_OPEN)
					dprint(FD_ZBD, "parse_zone_info: explicitly open zone = %d, 0x%lX, wp = 0x%lX, open zones = %d\n",
							j, z->start, z->wp, td->o.num_open_zones);
				if (z->cond == ZBD_ZONE_COND_IMP_OPEN)
					dprint(FD_ZBD, "parse_zone_info: implicitly open zone = %d, 0x%lX, wp = 0x%lX, open zones = %d\n",
							j, z->start, z->wp, td->o.num_open_zones);
				if (z->cond == ZBD_ZONE_COND_CLOSED)
					dprint(FD_ZBD, "parse_zone_info: closed zone = %d, 0x%lX, wp = 0x%lX, open zones = %d, attr = %d\n",
							j, z->start, z->wp, td->o.num_open_zones, z->attr);
				if (td->o.reset_active_zones_first) {
					if (!zbd_zone_reset(td, f, (p->start >> NVME_ZONE_LBA_SHIFT), false, td->o.ns_id))	{
						td_verror(td, errno, "resetting zone failed");
						log_err("%s: resetting wp 0x%lX failed (%d).\n",
							f->file_name, (p->start >> NVME_ZONE_LBA_SHIFT), errno);
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
					p->dev_wp = z->wp;
					p->cond = z->cond;
					/* If not zrwa mode and zone has zrwa allocation then issue finish zone when full */
					if (!td->o.zrwa_alloc && (z->attr & NVME_ZONE_ATTR_RWA_ALLOCATED)) {
						p->finish_zone = 1;
						dprint(FD_ZBD, "parse_zone_info: finish zone = %d, 0x%lX, wp = 0x%lX\n",
								j, z->start, z->wp);
					}
					if (!td->o.reset_all_zones_first) {
						td->o.open_zones[td->o.num_open_zones++] = j;
						td->num_open_zones++;
						p->open = 1;
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
				log_info("%s: invalid zone data, start = 0x%lX, start - 1 size = 0x%lX, size = 0x%lX\n",
					 f->file_name, p->start, p[-1].start, zone_size);
				ret = -EINVAL;
				goto out;
			}
		}
		z--;
		offset = z->start + zone_size;
		if (j >= nr_zones)
			break;
		nrz = zbd_report_zones(td, f, offset,
					    zones, ZBD_REPORT_MAX_ZONES);
		if (nrz < 0) {
			ret = nrz;
			log_info("fio: report zones (offset %llu) failed for %s (%d).\n",
			 	 (unsigned long long)(offset >> NVME_ZONE_LBA_SHIFT),
				 f->file_name, -ret);
			goto out;
		}
	}

	if (zbd_identify_ns(td, f, ns, ns_zns, td->o.ns_id)) {
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
					log_err("fio: %s iodepth = %d * blocksize = 0x%llX (0x%llX) is greater than zrwas = %d \n",
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
			zbd_verify_scheduler(f->file_name, scheduler);
			if (!zbd_verify_scheduler(f->file_name, scheduler)) {
				goto out;
			}
		}
	}  else {
		sprintf(scheduler, "[mq-deadline]");
		zbd_verify_scheduler(f->file_name, scheduler);
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

out:
	sfree(zbd_info);
	free(zones);
	free(ns);
	free(ns_zns);
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

	if (ret == 0) {
		f->zbd_info->model = zbd_model;
		f->zbd_info->max_open_zones = td->o.max_open_zones;
	}
	return ret;
}

void zbd_free_zone_info(struct fio_file *f)
{
	uint32_t refcount;

	assert(f->zbd_info);

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
		return 3;
	} else if ((overwrite_percentage >= 25) && (overwrite_percentage < 50)) {
		return 5;
	} else if ((overwrite_percentage > 10) && (overwrite_percentage < 25)) {
		return 8;
	} else if ((overwrite_percentage > 5) && (overwrite_percentage <= 10)) {
		return 10;
	} else if ((overwrite_percentage > 3) && (overwrite_percentage <= 5)) {
		return 17;
	} else if (overwrite_percentage == 3) {
		return 30;
	} else if (overwrite_percentage == 2) {
		return 40;
	} else {
		return 80;
	}
}

int zbd_setup_files(struct thread_data *td)
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

	if (!zbd_verify_sizes(td))
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

	z = &f->zbd_info->zone_info[f->min_zone];
	for (i = f->min_zone; i <= f->max_zone; i++, z++) {
		if (z->cond == ZBD_ZONE_COND_FULL) num_full_zones++;
	}

	return num_full_zones;
}

/* The caller must hold f->zbd_info->mutex. */
static bool is_zone_open(const struct thread_data *td, unsigned int zone_idx)
{
	int i;

	assert(td->o.job_max_open_zones == 0 || td->num_open_zones <= td->o.job_max_open_zones);
	assert(td->o.job_max_open_zones <= td->o.max_open_zones);
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
static int zbd_reset_range(struct thread_data *td, struct fio_file *f,
			   uint64_t offset, uint64_t length, bool open)
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
		if (!open)
			z->cond = ZBD_ZONE_COND_EMPTY;
		z->last_io = 0;
		z->io_q_count = 0;
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
static int zbd_reset_zone(struct thread_data *td, struct fio_file *f,
			  struct fio_zone_info *z, bool open)
{
	bool result = false;
	result = zbd_reset_range(td, f, z->start, zbd_zone_end(z) - z->start, open);
	dprint(FD_ZBD, "%s: resetting wp of zone %u, id = %d, result = %d\n", f->file_name,
		zbd_zone_nr(f->zbd_info, z), td->thread_number, result);

	return result;
}

/* The caller must hold f->zbd_info->mutex */
static void zbd_close_zone(struct thread_data *td, const struct fio_file *f,
			   unsigned int zone_idx)
{
	uint32_t open_zone_idx = 0;
	struct fio_zone_info *z;

	for (; open_zone_idx < td->o.num_open_zones; open_zone_idx++) {
		if (td->o.open_zones[open_zone_idx] == zone_idx)
			break;
	}
	if (open_zone_idx == td->o.num_open_zones)
		return;

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

		dprint(FD_ZBD, "%s(%s): closing zone %d, id = %d\n", __func__, f->file_name,
		   zone_idx, td->thread_number);

		memmove(td->o.open_zones + open_zone_idx,
			td->o.open_zones + open_zone_idx + 1,
			(ZBD_MAX_OPEN_ZONES - (open_zone_idx + 1)) *
			sizeof(td->o.open_zones[0]));
		td->o.num_open_zones--;
		td->num_open_zones--;
		td->o.num_filled_zones++;
		f->zbd_info->zone_info[zone_idx].open = 0;
		z->cond = ZBD_ZONE_COND_FULL;
		z->last_io = 0;
		z->io_q_count = 0;
		z->reset_zone = 0;
	}

	return;
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
	int i, res = 0;

	assert(min_bs);

	dprint(FD_ZBD, "%s: examining zones %u .. %u\n", f->file_name,
		zbd_zone_nr(f->zbd_info, zb), zbd_zone_nr(f->zbd_info, ze));
	for (z = zb; z < ze; z++) {
		uint32_t nz = z - f->zbd_info->zone_info;

		if (!zbd_zone_swr(z))
			continue;
		zone_lock(td, f, z);
		if (all_zones) {
			pthread_mutex_lock(&f->zbd_info->mutex);
			for (i = 0; i < td->o.num_open_zones; i++) {
				if (td->o.open_zones[i] == nz)
					zbd_close_zone(td, f, i);
			}
			pthread_mutex_unlock(&f->zbd_info->mutex);

			reset_wp = z->wp != z->start;
		} else {
			reset_wp = z->wp % min_bs != 0;
		}
		if (reset_wp) {
			dprint(FD_ZBD, "%s: resetting zone %u\n",
			       f->file_name,
			       zbd_zone_nr(f->zbd_info, z));
			if (zbd_reset_zone(td, f, z, false) < 0)
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
static void _zbd_reset_write_cnt(const struct thread_data *td,
				 const struct fio_file *f)
{
	assert(0 <= td->o.zrf.u.f && td->o.zrf.u.f <= 1);

	f->zbd_info->write_cnt = td->o.zrf.u.f ?
		min(1.0 / td->o.zrf.u.f, 0.0 + UINT_MAX) : UINT_MAX;
}

static void zbd_reset_write_cnt(const struct thread_data *td,
				const struct fio_file *f)
{
	pthread_mutex_lock(&f->zbd_info->mutex);
	_zbd_reset_write_cnt(td, f);
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
		_zbd_reset_write_cnt(td, f);
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

	zb = &f->zbd_info->zone_info[f->min_zone];
	ze = &f->zbd_info->zone_info[f->max_zone +1];
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

	if (!f->zbd_info || !td_write(td))
		return;

	zb = &f->zbd_info->zone_info[f->min_zone];
	ze = &f->zbd_info->zone_info[f->max_zone +1];
	zbd_init_swd(f);

	/*
	 * If data verification is enabled reset the affected zones before
	 * writing any data to avoid that a zone reset has to be issued while
	 * writing data, which causes data loss.
	 */
	if (td->o.verify != VERIFY_NONE &&
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

	dprint(FD_ZBD, "zbd_get_lowest_queued_offset: oldest pending io 0x%lX, io-offset= 0x%lX fio-wp=0x%lX q-count = %u, diff = 0x%lX\n",
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
	if (io_u->ddir == DDIR_READ)
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

/* Anything goes as long as it is not a constant. */
static uint32_t pick_random_zone_idx(const struct fio_file *f,
				     const struct io_u *io_u, int open_zones)
{
	return io_u->offset * open_zones / f->real_file_size;
}

int zbd_finish_full_zone(struct thread_data *td, struct fio_zone_info *z,
			const struct io_u *io_u, bool zone_io_finish)
{
    int i, ret = 0, open_zone_idx = -1;
    struct fio_file *f = io_u->file;
    uint32_t zone_idx;

    zone_idx = zbd_zone_idx(f, io_u->offset);

    if ((td->o.issue_zone_finish ||
    		z->cond == ZBD_ZONE_COND_EXP_OPEN ||
			z->cond == ZBD_ZONE_COND_IMP_OPEN || z->finish_zone) &&
    		zone_io_finish && z->cond != ZBD_ZONE_COND_FULL) {
		dprint(FD_ZBD, "%s(%s): Issuing BLKFINISHZONE on zone %d, id = %d\n", __func__,
				f->file_name, zone_idx, td->thread_number);
		ret = zbd_issue_finish(td, f, z->start, f->zbd_info->zone_size);
		if (ret < 0) {
			perror("Issuing finish failed with: ");
			return ret;
		}
		if (g_ow)
			z->ow_count = 0;

		z->cond = ZBD_ZONE_COND_FULL;
		z->last_io = 0;
		z->io_q_count = 0;
		z->finish_zone = 0;
		z->reset_zone = 0;
		z->wp = z->start + z->capacity;

		for (i = 0; i < td->o.num_open_zones; i++) {
			if (td->o.open_zones[i] == zone_idx)
				open_zone_idx = i;
		}

		/* check if zone was already closed */
		if (open_zone_idx != -1) {

			assert(open_zone_idx < td->o.num_open_zones);

			memmove(td->o.open_zones + open_zone_idx,
				td->o.open_zones + open_zone_idx + 1,
				(ZBD_MAX_OPEN_ZONES - (open_zone_idx + 1)) *
				sizeof(td->o.open_zones[0]));
			td->o.num_open_zones--;
			td->num_open_zones--;
			td->o.num_filled_zones++;
			f->zbd_info->zone_info[zone_idx].open = 0;
		}

    }
    return ret;
}

/**
 * zbd_end_zone_io - update zone status at command completion
 * @io_u: I/O unit
 * @z: zone info pointer
 *
 * If the write command made the zone full, close it.
 *
 * The caller must hold z->mutex.
 */
static void zbd_end_zone_io(struct thread_data *td, const struct io_u *io_u,
			    struct fio_zone_info *z)
{
	struct fio_file *f = io_u->file;
	int ret;

	if (io_u->ddir == DDIR_WRITE){

		if (td->o.issue_zone_finish || z->finish_zone) {
			if (((z->io_q_count == 0) && (z->last_io == ZONE_LAST_IO_COMPLETED) && td->o.zrwa_alloc) ||
				((((z->finish_zone || td->o.issue_zone_finish) && z->pending_ios == 0)
				&& !td->o.zrwa_alloc) && (io_u->offset + io_u->buflen >= zbd_zone_capacity_end(td, z)))) {
				ret = zbd_finish_full_zone(td, z, io_u, true);
				if (ret < 0)
					zbd_close_zone(td, f, z - f->zbd_info->zone_info);
				pthread_mutex_unlock(&f->zbd_info->mutex);
			}
		} else if (io_u->offset + io_u->buflen >= zbd_zone_capacity_end(td, z) && z->pending_ios == 0) {
			zbd_close_zone(td, f, z - f->zbd_info->zone_info);
		} else {
			if ((z->pending_ios == 0) &&
					((z->start + z->capacity) - (io_u->offset + io_u->buflen) > 0) &&
					(zbd_zone_capacity_end(td, z) - ((io_u->offset + io_u->buflen)) < io_u->buflen)) {

				io_u_quiesce(td);
				dprint(FD_ZBD, "%s: zbd_end_zone_io: at capacity (0x%llX, 0x%llX, 0x%lX), q-len = %u\n",
					f->file_name, io_u->offset, io_u->buflen, z->dev_wp, z->io_q_count);

				ret = zbd_finish_full_zone(td, z, io_u, true);
				assert(ret==0);
				pthread_mutex_unlock(&f->zbd_info->mutex);
			}
		}
	}
}

/*
 * Open a ZBD zone if it was not yet open. Returns true if either the zone was
 * already open or if opening a new zone is allowed. Returns false if the zone
 * was not yet open and opening a new zone would cause the zone limit to be
 * exceeded.
 */
static bool zbd_open_zone(struct thread_data *td, const struct io_u *io_u,
			  uint32_t zone_idx, bool force_open)
{
	const struct fio_file *f = io_u->file;
	struct fio_zone_info *z = &f->zbd_info->zone_info[zone_idx];
	bool res = true;
	int i, open_count = 0;

	if (!force_open) {

		if (z->cond == ZBD_ZONE_COND_OFFLINE)
			return false;

		if ((!td_random(td) || td->o.perc_rand[DDIR_WRITE] == 0) &&
				zbd_zone_full(td, f, z, 0)) {
			return false;
		}

		if ((td_random(td) || td->o.perc_rand[DDIR_WRITE] > 0) &&
				td->o.fill_empty_zones_first &&
				(td->o.num_open_zones < td->o.max_open_zones)) {

			if (zbd_zone_full(td, f, z, 0) ||
					((full_zones(f) + td->o.num_open_zones) > (f->max_zone - f->min_zone + 1))) {
				return false;
			}
		}

		/*
		 * Skip full zones with data verification enabled because resetting a
		 * zone causes data loss and hence causes verification to fail.
		 */
		if (td->o.verify != VERIFY_NONE && zbd_zone_full(td, f, z, io_u->buflen))
			return false;

		if (td->o.issue_zone_finish)
			z->finish_pct = td->o.finish_zone_pct;

		pthread_mutex_lock(&f->zbd_info->mutex);

		if (is_zone_open(td, zone_idx)) {
			/*
			 * If the zone is already open and going to be full by writes
			 * in-flight, handle it as a full zone instead of an open zone.
			 */
			if ((z->wp >= zbd_zone_capacity_end(td, z)) ||
					(((z->wp + io_u->buflen) > zbd_zone_capacity_end(td, z)) &&
					(((z->wp + io_u->buflen) - zbd_zone_capacity_end(td, z)) < io_u->buflen))) {
				res = false;
			}
			goto out;
		} else {
			/* if zone is open by another job then this job cannot open it. */
			if (z->open) {
				res = false;
				goto out;
			}
		}
		res = false;
		/* Zero means no limit */
		if ((td->o.max_open_zones > 0) && (td->o.num_open_zones >= td->o.max_open_zones))
			goto out;
	}

	 /* Check if number of open zones reached one of limits. */

	if ((td->num_open_zones >= g_mar) && !td->o.issue_zone_finish) {
		if ((!td_random(td) && td->o.max_open_zones &&
				td->o.num_open_zones == 1) || (td->o.max_open_zones &&
				td->o.num_open_zones == (td->o.max_open_zones - 1))) {
			/* Cover case where max zones are open and one is closed here but device
			 * has not marked zone as full.  This causes io errors if io is
			 * started on a new zone too soon.  Get number of open zones from device
			 * until less than max open zones
			 */

			i=0;
			open_count = zbd_get_open_count(f->fd, td->o.ns_id, td->o.zrwa_alloc);
			if (open_count > g_mar) {
			//	io_u_quiesce(td);
				while ((open_count > g_mar) && i < 1000) {
					usec_sleep(td,10);
					open_count = zbd_get_open_count(f->fd, td->o.ns_id, td->o.zrwa_alloc);
					i++;
				}
				assert(td->num_open_zones <= g_mar + 1);
				dprint(FD_ZBD, "%s(%s): id = %d, open zones = %d, i = %d\n",
					  __func__, f->file_name, td->thread_number, open_count, i);
			}
			if ( i == 1000)
				log_err("%s(%s): io_u_quiesce, zone = %d, full zones = %d, open zones = %d, max_open = %d, pending io = %d\n",
					__func__, f->file_name, zone_idx, full_zones(f), td->o.num_open_zones, td->o.max_open_zones, z->pending_ios);

		}
	}

	// Issue an explicit open with ZRWAA bit set via io-passtrhu.
	if (td->o.zrwa_alloc) {
		if (z->cond == ZBD_ZONE_COND_EMPTY ||
				z->cond == ZBD_ZONE_COND_CLOSED) {
			if(!zbd_issue_exp_open_zrwa(f, zone_idx, z->start >> NVME_ZONE_LBA_SHIFT, td->o.ns_id))
				goto out;
			z->cond = ZBD_ZONE_COND_EXP_OPEN;
		}
	} else {
		z->cond = ZBD_ZONE_COND_IMP_OPEN;
	}
	td->o.open_zones[td->o.num_open_zones++] = zone_idx;
	td->num_open_zones++;
	z->open = 1;
	dprint(FD_ZBD, "%s: opening zone %d, id = %d, open_zones = %d, total_open = %d%s \n",
			f->file_name, zone_idx, td->thread_number, td->o.num_open_zones, td->num_open_zones, td->o.zrwa_alloc ? " with ZRWA": "");
	dprint(FD_ZBD, "zbd_open_zone: zone %d start = 0x%lX, wp = 0x%lX\n",
			zone_idx, z->start, z->wp);
	res = true;

out:
	pthread_mutex_unlock(&f->zbd_info->mutex);
	return res;
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
	struct fio_file *f = io_u->file;
	struct fio_zone_info *z;
	unsigned int open_zone_idx = -1;
	unsigned int full_zone_idx = 0xFFFF;
	uint32_t zone_idx, new_zone_idx;
	int ret, i = 0;
	bool wait_zone_close, wrapped = false, try_again = true;
	bool find_random = (td_random(td) && td->o.perc_rand[DDIR_WRITE] > 0);

	assert(is_valid_offset(f, io_u->offset));

	zone_idx = zbd_zone_idx(f, io_u->offset);
	if (zone_idx < f->min_zone)
		zone_idx = f->min_zone;
	else if (zone_idx > f->max_zone)
		zone_idx = f->max_zone;
	dprint(FD_ZBD, "%s(%s): starting from zone %d id = %d, zones = %d (offset 0x%llX, buflen 0x%llX)\n",
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

		zone_lock(td, f, z);
		pthread_mutex_lock(&f->zbd_info->mutex);
		if (td->o.max_open_zones == 0 && td->o.job_max_open_zones == 0)
			goto examine_zone;
		if (td->o.num_open_zones < td->o.max_open_zones) {
			dprint(FD_ZBD, "%s(%s): open zones < max open\n",
			       __func__, f->file_name);
			goto open_other_zone;
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
			if (f->min_zone <= tmpz && tmpz <= f->max_zone) {
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

		if (new_zone_idx == zone_idx) {
			dprint(FD_ZBD, "%s(%s): found candidate zone %d, wp = 0x%lX, wp + bs = 0x%llX, finish = %d\n",
					__func__, f->file_name, new_zone_idx, z->wp, (z->wp + io_u->buflen), z->finish_zone);

			break;
		}
		zone_idx = new_zone_idx;
		pthread_mutex_unlock(&f->zbd_info->mutex);
		pthread_mutex_unlock(&z->mutex);
	}

	/* Both z->mutex and f->zbd_info->mutex are held. */

examine_zone:
	if ((z->wp + io_u->buflen <= zbd_zone_capacity_end(td, z)) &&
		(z->last_io != ZONE_LAST_IO_QUEUED)	&&
		is_valid_offset(f, z->start) &&
		(z->cond != ZBD_ZONE_COND_FULL)) {
		pthread_mutex_unlock(&f->zbd_info->mutex);
		goto out;
	}

	if (((z->wp + io_u->buflen) >= zbd_zone_capacity_end(td, z)) && z->finish_zone) {
		if (z->pending_ios == 0) {
		io_u->offset = z->wp;
		ret = zbd_finish_full_zone(td, z, io_u, true);
		assert(ret==0);
		}
	}

open_other_zone:

	pthread_mutex_unlock(&f->zbd_info->mutex);

    /* Only z->mutex is held. */
	/* Try to open a new zone. */

    if ((g_max_open_zones > 0) && (td->o.num_open_zones < td->o.max_open_zones)) {

    	dprint(FD_ZBD, "%s(%s): try to open another zone, open zones = %d, max = %d\n", __func__,
    	       f->file_name, td->o.num_open_zones, td->o.max_open_zones);

		srand(time(NULL));
		for (i = f->io_size / f->zbd_info->zone_size; i > 0; i--) {
			zone_idx++;

			pthread_mutex_unlock(&z->mutex);
			if (find_random) {
				zone_idx = rand() % (uint32_t)(f->io_size / f->zbd_info->zone_size);
				z = &f->zbd_info->zone_info[zone_idx];
				if ((z->cond == ZBD_ZONE_COND_FULL) && (full_zone_idx == 0xFFFF))
					full_zone_idx = zone_idx;
			} else {
				z++;
			}
			if (!is_valid_offset(f, z->start)) {
				/* Wrap-around. */
				zone_idx = f->min_zone;
				z = &f->zbd_info->zone_info[zone_idx];
			}
			assert(is_valid_offset(f, z->start));

			if ((find_random || wrapped) && td->o.time_based) {
				if ((full_zones(f) + td->num_open_zones) >= (f->max_zone - f->min_zone + 1)) {
					if (!z->open && (z->cond == ZBD_ZONE_COND_FULL)) {
				    	if (zbd_open_zone(td, io_u, zone_idx, true)) {
							goto out;
				    	}
					}
				}
			}

			/* if last iteration and have not found not open or non-full zone then try to find one sequentially */
			if (find_random && (i==1) && (z->open || (z->cond == ZBD_ZONE_COND_FULL))) {
				/* Wrap-around. */
				zone_idx = f->min_zone;
				z = &f->zbd_info->zone_info[zone_idx];
				find_random = false;
				wrapped = true;
				i = f->io_size / f->zbd_info->zone_size;
			}
			pthread_mutex_lock(&z->mutex);
			if (z->open)
				continue;
			if ((z->cond == ZBD_ZONE_COND_FULL) && !td->o.time_based) {
				if ((td->o.num_filled_zones < (td->o.num_zones - td->o.num_open_zones)) &&
						((full_zones(f) + td->num_open_zones) >= td->o.num_zones)) {
			    	if (zbd_open_zone(td, io_u, zone_idx, true)) {
						goto out;
			    	} else {
			    		continue;
			    	}
				} else {
					continue;
				}
			}
			if (zbd_open_zone(td, io_u, zone_idx, false))
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

		zone_lock(td, f, z);
		if ((z->wp + io_u->buflen <= zbd_zone_capacity_end(td, z)) &&
				is_valid_offset(f, z->start) && (z->cond != ZBD_ZONE_COND_FULL)) {
			goto out;
		}
		pthread_mutex_lock(&f->zbd_info->mutex);
	}

	/* Did not open an existing zone.
	 * Check if number of open zones reached one of limits.
	 */
	wait_zone_close =  ((td->o.num_open_zones == (f->max_zone - f->min_zone)) ||
		(!td_random(td) && td->o.max_open_zones && td->o.num_open_zones == 1) ||
		(td->o.max_open_zones &&
		(td->o.num_open_zones == td->o.max_open_zones)));

	/*
	 * When number of open zones reaches to one of limits, wait for
	 * zone close before opening a new zone.
	 */
	if (wait_zone_close) {
		if (z->cond != ZBD_ZONE_COND_FULL) {
			dprint(FD_ZBD, "%s(%s): io_u_quiesce, full zones = %d, open zones = %d, max_open = %d, io_q_count = %d, finish = %d\n",
					__func__, f->file_name, full_zones(f), td->o.num_open_zones, td->o.max_open_zones, z->io_q_count, z->finish_zone);
			io_u_quiesce(td);
			if (try_again) {
				try_again = false;
				goto open_other_zone;
			}
		}
	}

	pthread_mutex_unlock(&f->zbd_info->mutex);
	pthread_mutex_unlock(&z->mutex);
	dprint(FD_ZBD, "%s(%s): did not open another zone, id = %d, zone = %d, zone_idx = %d, open zones = %d\n", __func__,
	       f->file_name, td->thread_number, zone_idx, i, td->o.num_open_zones);
	return NULL;

out:
	dprint(FD_ZBD, "%s(%s): returning zone %d, offset = 0x%lX, id = %d\n", __func__, f->file_name,
	       zone_idx, z->start, td->thread_number);
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

	if (!zbd_open_zone(td, io_u, z - f->zbd_info->zone_info, false)) {
		pthread_mutex_unlock(&z->mutex);
		z = zbd_convert_to_open_zone(td, io_u);
		assert(z);
	}

	if (z->verify_block * min_bs >= z->capacity)
		log_err("%s: %d * %d >= %llu\n", f->file_name, z->verify_block,
			min_bs, (unsigned long long)z->capacity);
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
	struct fio_file *f = io_u->file;
	struct fio_zone_info *z1, *z2;
	const struct fio_zone_info *const zf =
		&f->zbd_info->zone_info[f->min_zone];

	/*
	 * Find first non-empty zone in case of sequential I/O and to
	 * the nearest non-empty zone in case of random I/O.
	 * Pick first available in case of td->o.read_beyond_wp
	 */
	for (z1 = zb, z2 = zb - 1; z1 < zl || z2 >= zf; z1++, z2--) {
		if (z1 < zl && z1->cond != ZBD_ZONE_COND_OFFLINE) {
			zone_lock(td, f, z1);
			if ((z1->start + min_bs <= z1->wp) ||
					(td->o.read_beyond_wp && ((io_u->offset + io_u->buflen) < (z1->start + z1->capacity))))
				return z1;
			pthread_mutex_unlock(&z1->mutex);
		} else if (!td_random(td)) {
			break;
		}
		if (td_random(td) && z2 >= zf &&
		    z2->cond != ZBD_ZONE_COND_OFFLINE) {
			zone_lock(td, f, z2);
			if ((z2->start + min_bs <= z2->wp) ||
					(td->o.read_beyond_wp && ((io_u->offset + io_u->buflen) < (z2->start + z2->capacity))))
				return z2;
			pthread_mutex_unlock(&z2->mutex);
		}
	}
	dprint(FD_ZBD, "%s: adjusting random read offset failed\n",
	       f->file_name);
	return NULL;
}

/**
 * zbd_queue_io - update the write pointer of a sequential zone
 * @td: fio thread data.
 * @io_u: I/O unit
 * @success: Whether or not the I/O unit has been queued successfully
 * @q: queueing status (busy, completed or queued).
 *
 * For write and trim operations, update the write pointer of the I/O unit
 * target zone.
 * For zone append operation, release the zone mutex
 */
static void zbd_queue_io(struct thread_data *td,
		struct io_u *io_u, int q, bool success)
{
	const struct fio_file *f = io_u->file;
	struct zoned_block_device_info *zbd_info = f->zbd_info;
	struct fio_zone_info *z;
	uint32_t zone_idx;
	uint64_t zone_end;
	int ret;

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
		if (io_u->offset >= (z->dev_wp + ZRWA_SIZE_BYTES))
			z->dev_wp += (io_u->offset - (z->dev_wp + ZRWA_SIZE_BYTES));
	} else if (io_u->ddir == DDIR_WRITE) {
		z->dev_wp = io_u->offset;
	}

	dprint(FD_ZBD, "%s: queued I/O (0x%llX, 0x%llX, 0x%lX) for zone %u, q-len = %u, id = %d\n",
		f->file_name, io_u->offset, io_u->buflen, z->dev_wp, zone_idx, z->io_q_count, td->thread_number);

	switch (io_u->ddir) {
	case DDIR_WRITE:
		z->pending_ios++;
		zone_end = min((uint64_t)(io_u->offset + io_u->buflen),
			       zbd_zone_capacity_end(td, z));

		if (zbd_zone_capacity_end(td, z) == io_u->offset + io_u->buflen)
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

	if (q == FIO_Q_COMPLETED && !io_u->error)
		zbd_end_zone_io(td, io_u, z);

unlock:
	if (!success || q != FIO_Q_QUEUED || td->o.zone_append) {
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
			ret = pthread_mutex_unlock(&z->mutex);
			assert(ret == 0);
			if (!success || q != FIO_Q_QUEUED)
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
 * For zone append operation we don't hold zone lock
 * @td: fio thread data.
 * @io_u: I/O unit
 */
static void zbd_put_io(struct thread_data *td, const struct io_u *io_u)
{
	const struct fio_file *f = io_u->file;
	struct zoned_block_device_info *zbd_info = f->zbd_info;
	struct fio_zone_info *z;
	int ret;
	uint32_t zone_idx, zone_q_io_idx;

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

	dprint(FD_ZBD, "%s: terminate I/O (0x%llX, 0x%llX) for zone %u, id = %d\n",
		f->file_name, io_u->offset, io_u->buflen, zone_idx, td->thread_number);

	if (td->o.zrwa_alloc && td->o.dynamic_qd && (io_u->ddir == DDIR_WRITE)) {
		if (!z->io_q_count) {
			printf("%s: Error: zone io queue is empty !! offset 0x%llX \n", __func__, io_u->offset);
			assert(0);
		}
		for (int i = 0; i < z->io_q_count; i++) {
			dprint(FD_ZBD, "z->zone_io_q[%d] = 0x%lX \n", i, z->zone_io_q[i]);
			if ((z->zone_io_q[i] + io_u->buflen) >= zbd_zone_capacity_end(td, z)) {
				z->last_io = ZONE_LAST_IO_COMPLETED;
				dprint(FD_ZBD, "last io = z->zone_io_q[%d] = 0x%llX \n", i, (z->zone_io_q[i] + io_u->buflen));
			}
		}

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

	if (td->o.exp_commit) {
	    if (io_u->buflen < td->o.commit_gran) {
		    if ((io_u->offset + io_u->buflen) >= td->o.commit_gran &&
			    !((io_u->offset + io_u->buflen) % td->o.commit_gran)) {
		    if(!zbd_issue_commit_zone(f, zone_idx,
		    		(((io_u->offset + io_u->buflen) >> NVME_ZONE_LBA_SHIFT) - 1),
		    		(z->start >> NVME_ZONE_LBA_SHIFT), td->o.ns_id))
			    dprint(FD_ZBD, "commit zone failed on zone %d, at offset %llu\n",
							    zone_idx, io_u->offset + io_u->buflen);
		    }
	    } else {
		    //In case io_u->buflen >= td->o.commit_gran
		    if(!zbd_issue_commit_zone(f, zone_idx,
		    		(((io_u->offset + io_u->buflen) >> NVME_ZONE_LBA_SHIFT) - 1),
		    		z->start >> NVME_ZONE_LBA_SHIFT, td->o.ns_id))
			    dprint(FD_ZBD, "commit zone failed on zone %d, at offset %llu\n",
				    zone_idx, io_u->offset + io_u->buflen);
	    }
	}

	zbd_end_zone_io(td, io_u, z);

	if (td->o.zone_append) {
		pthread_mutex_lock(&z->mutex);
		if (z->pending_ios > 0) {
			/*
			 * Other threads may be waiting for pending I/O's to
			 * complete for this zone. Notify them.
			 */
			if (!z->pending_ios)
				pthread_cond_broadcast(&z->reset_cond);
		}
	}

	ret = pthread_mutex_unlock(&z->mutex);
	assert(ret == 0);
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

	zone_idx = zbd_zone_idx(f, f->last_pos[ddir]);
	z = &f->zbd_info->zone_info[zone_idx];

	/*
	 * When the zone capacity is smaller than the zone size and the I/O is
	 * sequential write, skip to zone end if the latest position is at the
	 * zone capacity limit.
	 */
	if (z->capacity < f->zbd_info->zone_size && !td_random(td) &&
	    ddir == DDIR_WRITE &&
	    f->last_pos[ddir] >= zbd_zone_end(z)) {
		dprint(FD_ZBD,
		       "%s: Jump from zone capacity limit to zone end:"
		       " (%lu -> %lu) for zone %u (%ld)\n",
		       f->file_name, f->last_pos[ddir], zbd_zone_end(z),
		       zbd_zone_nr(f->zbd_info, z), z->capacity);
		td->io_skip_bytes += zbd_zone_end(z) - f->last_pos[ddir];
		f->last_pos[ddir] = zbd_zone_end(z);
	}

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
	if (td->zone_bytes >= td->o.zone_size ||
	    f->last_pos[ddir] >= zbd_zone_end(z) ||
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

	if ((((td->o.max_open_zones > 0) && (td->num_open_zones > 0)) ||
			((td->o.max_open_zones == 0) && io_u->file->zbd_info->sectors_with_data > 0)) &&
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
	struct fio_file *f = io_u->file;
	uint32_t zone_idx, zone_idx_b;
	struct fio_zone_info *zb, *zl, *orig_zb;
	uint32_t orig_len = io_u->buflen;
	uint32_t min_bs = td->o.min_bs[io_u->ddir];
	uint64_t new_len;
	int64_t range;
	int rand_value;

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
		if (io_u->offset + io_u->buflen <= zb->start + zb->capacity) {
			return io_u_accept;
		}
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
	zone_lock(td, f, zb);

	switch (io_u->ddir) {
	case DDIR_READ:
		if (td->runstate == TD_VERIFYING && td_write(td)) {
			zb = zbd_replay_write_order(td, io_u, zb);
			pthread_mutex_unlock(&zb->mutex);
			goto accept;
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
			zl = &f->zbd_info->zone_info[f->max_zone + 1];
			zb = zbd_find_zone(td, io_u, zb, zl);
			if (!zb) {
				/* if not able to find another written to zone and random reads
				 * then pick random offset in current zone or start of zone for sequential
				 * if read_beyond_wp is set
				 * */
				zb = orig_zb;
				if (td->o.read_beyond_wp) {
					if (td_random(td) || (td->o.perc_rand[DDIR_WRITE] > 0)) {
						srand(g_rand_seed++);
						io_u->offset = zb->start + (rand() % (uint32_t)(zb->capacity / io_u->buflen)) * io_u->buflen  ;
						if (io_u->offset + io_u->buflen <= zb->start + zb->capacity) {
							return io_u_accept;
						}
					} else {
						io_u->offset = zb->start;
						return io_u_accept;
					}
				} else {
					log_err("%s: zbd_find_zone(0x%llX, 0x%llX) for read failed, id = %d\n",
						   f->file_name, io_u->offset, io_u->buflen, td->thread_number);
					goto eof;
				}
			}
			/*
			 * zbd_find_zone() returned a zone with a range of at
			 * least min_bs.
			 */
			if (!td_random(td))
				io_u->offset = zb->start;
			if (!td->o.read_beyond_wp) {
				range = zb->wp - zb->start;
				assert(range >= min_bs);
			} else {
				io_u->offset = ((zb->wp + io_u->buflen) < zb->capacity) ? zb->wp : zb->start;
				return io_u_accept;
			}
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

		/* Check if sequential write and have open zone already.
		 * Then proceed immediately to set offset.
		 */
		if (!td_random(td) || td->o.perc_rand[DDIR_WRITE] == 0) {
			if (td->o.num_open_zones > 0) {
				zl = &f->zbd_info->zone_info[td->o.open_zones[0]];
				if (zb != zl) {
					pthread_mutex_unlock(&zb->mutex);
					zone_lock(td, f, zl);
					zb = zl;
					zone_idx_b = zbd_zone_idx(f, zb->wp);
				}
				if (zbd_zone_full(td, f, zb, 0)) {
					pthread_mutex_unlock(&zb->mutex);
					zb = zbd_convert_to_open_zone(td, io_u);
					if (!zb) {
						/*
						 * If sequential write and not timed then
						 * if have not filled all zones in work area and
						 * cannot open a new zone then pick next zone
						 * if timed and last zone then wrap around
						 *
						 */
						zone_idx_b++;
						if (zone_idx_b > f->max_zone)
							zone_idx_b = f->min_zone;
						zb = &f->zbd_info->zone_info[zone_idx_b];
						zb->reset_zone = true;
						if (td->o.time_based) {
							goto reset;
						} else {
							if ((td->o.num_filled_zones + td->o.num_open_zones) < td->o.num_zones) {
								goto eof;
							} else {
								goto reset;
							}
						}
					}
				} else {
					goto proceed;
				}
			}
		} else {
			/* Check if random write and have max_open_zones
			 * open zone already. Then select a random zone and
			 * proceed immediately to set offset for write otherwise go
			 * through normal open and convert to open zone path.
			 */

			if ((td->o.max_open_zones > 0) && (td->o.num_open_zones == td->o.max_open_zones)) {
				if (g_rand_seed == 0)
					g_rand_seed = time(NULL);
				srand(g_rand_seed++);
				zone_idx = rand() % (uint32_t)td->o.max_open_zones;
				zone_idx_b = td->o.open_zones[zone_idx];
				zl = &f->zbd_info->zone_info[zone_idx_b];
				if (zb != zl) {
					pthread_mutex_unlock(&zb->mutex);
					zone_lock(td, f, zl);
					zb = zl;
				}
				if (!zbd_zone_full(td, f, zb, io_u->buflen)) {
					goto proceed;
				}
			}
		}

		if (!zbd_open_zone(td, io_u, zone_idx_b, false)) {
			if ((zb->cond == ZBD_ZONE_COND_FULL) &&
					td->o.time_based && (is_zone_open(td, zone_idx_b)) &&
					((full_zones(f) + td->num_open_zones) >= (f->max_zone - f->min_zone + 1))) {
			      zb->reset_zone = true;
			} else {
				if (!td->o.time_based &&
						(ddir_rw_sum(td->io_bytes) >=
						((td->zbd_finish_capacity + (td->zbd_ow_blk_count * io_u->buflen))  *
								(f->max_zone - f->min_zone + 1)))) {
					goto eof;
				}
				pthread_mutex_unlock(&zb->mutex);
				zb = zbd_convert_to_open_zone(td, io_u);
				if (!zb) {
					/*
					 * If time based then
					 * reset zone if cannot open a new zone
					 */
					if ((td->o.time_based) &&
							(!td_random(td) || td->o.perc_rand[DDIR_WRITE] == 0)) {
						zb = orig_zb;
						zb->reset_zone = 1;
						zone_idx_b = zb - f->zbd_info->zone_info;
					} else {
						goto eof;
					}
				} else {
					if ((zb->wp + io_u->buflen) > zbd_zone_capacity_end(td, zb)) {
						zb->reset_zone = 1;
					}
				}
			}
		}
		/* Check whether the zone reset threshold has been exceeded */
		if (td->o.zrf.u.f) {
			if (f->zbd_info->sectors_with_data >=
			    f->io_size * td->o.zrt.u.f &&
			    zbd_dec_and_reset_write_cnt(td, f)) {
				zb->reset_zone = 1;
			}
		}

		/* Reset the zone pointer if necessary */
		/*
		 * Since previous write requests may have been submitted
		 * asynchronously and since we will submit the zone
		 * reset synchronously, wait until previously submitted
		 * write requests have completed before issuing a
		 * zone reset.
		 * zone reset. For append request release the zone lock
		 * as other threads will acquire it at the time of
		 * zbd_put_io.
		 */
		if (zb->reset_zone || zbd_zone_full(td, f, zb, 0)) {
			assert(td->o.verify == VERIFY_NONE);
			/* If filling empty zones first attempt to open an empty zone rather
			 * than reset current zone*/
			if ((td->o.fill_empty_zones_first) &&
					(td_random(td) || td->o.perc_rand[DDIR_WRITE] > 0)
					&& zbd_zone_full(td, f, zb, 0)) {

				if ((td->o.num_filled_zones + td->o.num_open_zones) < td->o.num_zones) {
					if (!td->o.time_based) {
						pthread_mutex_unlock(&zb->mutex);
						zb = zbd_convert_to_open_zone(td, io_u);
					}
					if (!zb) {
						if (td->o.time_based) {
							zb = orig_zb;
							zb->reset_zone = 1;
							pthread_mutex_lock(&zb->mutex);
						} else {
							goto eof;
						}
					} else {
						zb->reset_zone = true;
					}
				} else {
					zb->reset_zone = true;
				}
			} else {
				zb->reset_zone = true;
			}
		}

reset:

		if (zb->reset_zone) {
			if (td->o.zone_append)
				pthread_mutex_unlock(&zb->mutex);
			io_u_quiesce(td);

			if (td->o.zone_append) {
				/*
				 * While processing the current thread queued
				 * requests the other thread may have already
				 * done zone reset so need to check zone full
				 * condition again.
				 */
				if (!zbd_zone_full(td, f, zb, 0))
					goto proceed;
				/*
				 * Wait for the pending requests to be completed
				 * else we are ok to reset this zone.
				 */
				if (zb->pending_ios) {
					pthread_cond_wait(&zb->reset_cond, &zb->mutex);
					goto proceed;
				}
			}
			if (zbd_reset_zone(td, f, zb, zb->open) < 0)
				goto eof;
			zb->reset_zone = 0;
			pthread_mutex_lock(&zb->mutex);

			/* Notify other threads waiting for zone mutex */
			if (td->o.zone_append)
				pthread_cond_broadcast(&zb->reset_cond);

			if (td->o.zrwa_alloc) {
				if(!zbd_issue_exp_open_zrwa(f,
				zbd_zone_idx(f, zb->start), (zb->start >> NVME_ZONE_LBA_SHIFT), td->o.ns_id))
					return -1;
				zb->cond = ZBD_ZONE_COND_EXP_OPEN;
			}

			if (zb->capacity < io_u->buflen) {
				log_err("zone capacity %llu smaller than block size 0x%llX\n",
					(unsigned long long)zb->capacity,
					io_u->buflen);
				goto eof;
			}
		}
proceed:
		/*
		 * Check for zone full condition again. For zone append request
		 * the zone may already be reset, written and full while we
		 * were waiting for our turn.
		 */
		if (zbd_zone_full(td, f, zb, 0)) {
			goto reset;
		}

		/* Make writes occur at the write pointer */
		assert(!zbd_zone_full(td, f, zb, 0));
		io_u->offset = zb->wp;
		dprint(FD_ZBD,"Adjust_Block: Issuing write to offset 0x%llX, dev_wp = 0x%lX, bs = 0x%llX, job = %d\n",
						       io_u->offset, zb->dev_wp, io_u->buflen, td->thread_number);

		/*
		 * Support zone append for both regular and zoned block
		 * device.
		 */
		if (td->o.zone_append) {
			if (f->zbd_info->model == ZBD_NONE)
				io_u->zone_start_offset = zb->wp;
			else
				io_u->zone_start_offset = zb->start;
		}

		// If overwrites are set, then issue a write to previously
		// written location, which is wp - buflen, ensure the offset
		// is greater zone start + buflen, so that the IO are not
		// sent to previous zone.
		if ((td->o.zrwa_overwrite_percent && td->o.zrwa_alloc) &&
				(zb->cond == ZBD_ZONE_COND_EXP_OPEN)) {
			if (g_rand_seed == 0)
				g_rand_seed = time(NULL);
		   // Issue write to a zone until ow_count reaches td->zbd_ow_blk_count
		   // During finishing a zone, reset ow_count 0
		   if (zb->ow_count < td->zbd_ow_blk_count &&
				   (io_u->offset >= zb->start + io_u->buflen) &&
				   io_u->offset >= zb->dev_wp + io_u->buflen) {
			   if (td->o.zrwa_rand_ow) {
				   srand(g_rand_seed++);
				   rand_value = rand();
				   if (!(rand_value % td->o.zrwa_divisor)) {
					   if (zb->prev_ow_lba != (io_u->offset - io_u->buflen)) {
						   io_u->offset -= io_u->buflen;
						   zb->prev_ow_lba = io_u->offset;
						   zb->ow_count++;
						   td->ts.zrwa_overwrite_bytes += io_u->buflen;
					       dprint(FD_ZBD,"Issuing overwrite at offset 0x%llX, start= 0x%lX, wp= 0x%lX, dev_wp = 0x%lX, count = %d, que = %d\n",
							       io_u->offset, zb->start, zb->wp, zb->dev_wp, zb->ow_count, zb->io_q_count);
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
					       dprint(FD_ZBD,"Issuing overwrite at offset 0x%llX, start= 0x%lX, wp= 0x%lX, dev_wp = 0x%lX, count = %d, que = %d\n",
							       io_u->offset, zb->start, zb->wp, zb->dev_wp, zb->ow_count, zb->io_q_count);
					   }
				   }
				}
			}
		}

		if (!is_valid_offset(f, io_u->offset)) {
			dprint(FD_ZBD, "Dropped request with offset 0x%llX\n",
			       io_u->offset);
			goto eof;
		}

		/*
		 * Make sure that the buflen is a multiple of the minimal
		 * block size. Give up if shrinking would make the request too
		 * small.
		 */
		new_len = min((unsigned long long)io_u->buflen,
			      zbd_zone_capacity_end(td, zb) - io_u->offset);
		new_len = new_len / min_bs * min_bs;
		if (new_len == io_u->buflen)
			goto accept;
		if (new_len >= min_bs) {
			io_u->buflen = new_len;
			dprint(FD_IO, "Changed length from %u into %llu\n",
			       orig_len, io_u->buflen);
			goto accept;
		}
		dprint(FD_ZBD,"Zone remainder 0x%llX smaller than block size 0x%llX\n",
				((io_u->offset + io_u->buflen) - zbd_zone_capacity_end(td, zb)),
			io_u->buflen);
		log_err("Zone remainder %lld smaller than minimum block size %d\n",
			(zbd_zone_capacity_end(td, zb) - io_u->offset),
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
