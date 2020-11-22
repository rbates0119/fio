/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 */
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "file.h"
#include "fio.h"
#include "lib/pow2.h"
#include "log.h"
#include "oslib/asprintf.h"
#include "smalloc.h"
#include "verify.h"
#include "zbd_types.h"

#include <linux/blkzoned.h>
#include <linux/nvme_ioctl.h>

#define	NVME_ZONE_MGMT_SEND_ZRWAA	9
#define NVME_ZONE_ACTION_OPEN       	0x3
#define NVME_ZONE_ACTION_COMMIT		0x11


/*
 * Read up to 255 characters from the first line of a file. Strip the trailing
 * newline.
 */
char *read_file(const char *path)
{
	char line[256], *p = line;
	FILE *f;

	f = fopen(path, "rb");
	if (!f)
		return NULL;
	if (!fgets(line, sizeof(line), f))
		line[0] = '\0';
	strsep(&p, "\n");
	fclose(f);

	return strdup(line);
}

int blkzoned_get_zoned_model(struct thread_data *td, struct fio_file *f,
			     enum zbd_zoned_model *model)
{
	const char *file_name = f->file_name;
	char *zoned_attr_path = NULL;
	char *model_str = NULL;
	struct stat statbuf;
	char *sys_devno_path = NULL;
	char *part_attr_path = NULL;
	char *part_str = NULL;
	char sys_path[PATH_MAX];
	ssize_t sz;
	char *delim = NULL;

	*model = ZBD_HOST_MANAGED;
	return 0;

	if (f->filetype != FIO_TYPE_BLOCK) {
		*model = ZBD_IGNORE;
		return 0;
	}

	if (stat(file_name, &statbuf) < 0)
		goto out;

	if (asprintf(&sys_devno_path, "/sys/dev/block/%d:%d",
		     major(statbuf.st_rdev), minor(statbuf.st_rdev)) < 0)
		goto out;

	sz = readlink(sys_devno_path, sys_path, sizeof(sys_path) - 1);
	if (sz < 0)
		goto out;
	sys_path[sz] = '\0';

	/*
	 * If the device is a partition device, cut the device name in the
	 * canonical sysfs path to obtain the sysfs path of the holder device.
	 *   e.g.:  /sys/devices/.../sda/sda1 -> /sys/devices/.../sda
	 */
	if (asprintf(&part_attr_path, "/sys/dev/block/%s/partition",
		     sys_path) < 0)
		goto out;
	part_str = read_file(part_attr_path);
	if (part_str && *part_str == '1') {
		delim = strrchr(sys_path, '/');
		if (!delim)
			goto out;
		*delim = '\0';
	}

	if (asprintf(&zoned_attr_path,
		     "/sys/dev/block/%s/queue/zoned", sys_path) < 0)
		goto out;

	model_str = read_file(zoned_attr_path);
	if (!model_str)
		goto out;
	dprint(FD_ZBD, "%s: zbd model string: %s\n", file_name, model_str);
	if (strcmp(model_str, "host-aware") == 0)
		*model = ZBD_HOST_AWARE;
	else if (strcmp(model_str, "host-managed") == 0)
		*model = ZBD_HOST_MANAGED;
out:
	free(model_str);
	free(zoned_attr_path);
	free(part_str);
	free(part_attr_path);
	free(sys_devno_path);
	return 0;
}

static uint64_t zone_capacity(struct blk_zone_report *hdr,
			      struct blk_zone *blkz)
{
#ifdef CONFIG_HAVE_REP_CAPACITY
	if (hdr->flags & BLK_ZONE_REP_CAPACITY)
		return blkz->capacity << 9;
#endif
	return blkz->len << 9;
}

int blkzoned_report_zones(struct thread_data *td, struct fio_file *f,
			  uint64_t offset, struct zbd_zone *zones,
			  unsigned int nr_zones)
{
	struct blk_zone_report *hdr = NULL;
	struct blk_zone *blkz;
	struct zbd_zone *z;
	unsigned int i;
	int fd = -1, ret;

	fd = open(f->file_name, O_RDONLY | O_LARGEFILE);
	if (fd < 0)
		return -errno;

	hdr = calloc(1, sizeof(struct blk_zone_report) +
			nr_zones * sizeof(struct blk_zone));
	if (!hdr) {
		ret = -ENOMEM;
		goto out;
	}

	hdr->nr_zones = nr_zones;
	hdr->sector = offset >> 9;
	ret = ioctl(fd, BLKREPORTZONE, hdr);
	if (ret) {
		ret = -errno;
		goto out;
	}

	nr_zones = hdr->nr_zones;
	blkz = (void *) hdr + sizeof(*hdr);
	z = &zones[0];
	for (i = 0; i < nr_zones; i++, z++, blkz++) {
		z->start = blkz->start << 9;
		z->wp = blkz->wp << 9;
		z->len = blkz->len << 9;
		z->capacity = zone_capacity(hdr, blkz);

		switch (blkz->type) {
		case BLK_ZONE_TYPE_CONVENTIONAL:
			z->type = ZBD_ZONE_TYPE_CNV;
			break;
		case BLK_ZONE_TYPE_SEQWRITE_REQ:
			z->type = ZBD_ZONE_TYPE_SWR;
			break;
		case BLK_ZONE_TYPE_SEQWRITE_PREF:
			z->type = ZBD_ZONE_TYPE_SWP;
			break;
		default:
			td_verror(td, errno, "invalid zone type");
			log_err("%s: invalid type for zone at sector %llu.\n",
				f->file_name, (unsigned long long)offset >> 9);
			ret = -EIO;
			goto out;
		}

		switch (blkz->cond) {
		case BLK_ZONE_COND_NOT_WP:
			z->cond = ZBD_ZONE_COND_NOT_WP;
			break;
		case BLK_ZONE_COND_EMPTY:
			z->cond = ZBD_ZONE_COND_EMPTY;
			break;
		case BLK_ZONE_COND_IMP_OPEN:
			z->cond = ZBD_ZONE_COND_IMP_OPEN;
			break;
		case BLK_ZONE_COND_EXP_OPEN:
			z->cond = ZBD_ZONE_COND_EXP_OPEN;
			break;
		case BLK_ZONE_COND_CLOSED:
			z->cond = ZBD_ZONE_COND_CLOSED;
			break;
		case BLK_ZONE_COND_FULL:
			z->cond = ZBD_ZONE_COND_FULL;
			break;
		case BLK_ZONE_COND_READONLY:
		case BLK_ZONE_COND_OFFLINE:
		default:
			/* Treat all these conditions as offline (don't use!) */
			z->cond = ZBD_ZONE_COND_OFFLINE;
			break;
		}
	}

	ret = nr_zones;
out:
	free(hdr);
	close(fd);

	return ret;
}

int zbd_zone_mgmt_report(struct thread_data *td, struct fio_file *f,
			  uint64_t offset, struct zbd_zone *zones,
			  unsigned int nr_zones, bool simulation)
{
	struct nvme_zone_report_header	*hdr = NULL;
	struct nvme_zone_log *zone_log;
	struct zbd_zone *z;
	unsigned int i;
	int fd = -1, ret;
	int log_len;
	void * buff;
	uint16_t zone_info_sz;
	struct nvme_passthru_cmd cmd;
	char file_name[20];
	memset(&cmd, 0, sizeof(cmd));

	zone_info_sz = sizeof(struct nvme_zone_log);
	log_len = sizeof(struct nvme_zone_report_header) + (sizeof(struct nvme_zone_log) * nr_zones);
	buff = calloc(1, log_len);
	if (!buff) {
		ret = -ENOMEM;
		goto out;
	}

	if (!simulation) {

		fd = f->fd;
		if (fd < 0) {
			fd = open(f->file_name, O_RDWR | O_LARGEFILE);
			if (fd < 0)
				return -errno;
		}

		cmd.opcode		=  nvme_cmd_zone_mgmt_recv;
		cmd.nsid		= td->o.ns_id;
		cmd.cdw10		= offset & 0xffffffff;
		cmd.cdw11		= offset >> 32;
		cmd.cdw13		= 0;
		cmd.cdw12		= (log_len / 4) - 1,
		cmd.addr		= (__u64)(uintptr_t)buff;
		cmd.data_len	= log_len;

		ret = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
		if (ret) {
			ret = -errno;
			dprint(FD_ZBD, "zbd_zone_mgmt_report: Failed, ret = %d\n", ret);
			goto out;
		}
	} else {
		sprintf(file_name, "namespace_%d.bin",nr_zones);

		fd = open(file_name, O_RDONLY, S_IRUSR);
		if (fd < 0) {
			return -errno;
		}
		ret = read(fd, buff, log_len);
		if (ret < log_len) {
			close(fd);
			return -1;
		}
	}

	hdr = (struct nvme_zone_report_header *)buff;
	buff += sizeof(*hdr);
	nr_zones = hdr->nr_zones;
	z = &zones[0];
	dprint(FD_ZBD, "zbd_zone_mgmt_report: num zones = %d, id = %d\n", nr_zones, td->thread_number);
	for (i = 0; i < nr_zones; i++, z++) {
		zone_log = (struct nvme_zone_log *)buff;

		z->start = zone_log->slba << 12;
		z->wp = zone_log->wp << 12;
		z->capacity = zone_log->capacity << 12;
		z->attr = zone_log->zone_attrs;
		log_err("zbd_zone_mgmt_report %s: for zone at slba 0x%llX, wp = 0x%llX, capacity =  = 0x%llX, state = %d.\n",
			file_name, zone_log->slba, zone_log->wp, zone_log->capacity, zone_log->zone_state);

		switch (zone_log->zone_type) {
		case BLK_ZONE_TYPE_CONVENTIONAL:
			z->type = ZBD_ZONE_TYPE_CNV;
			break;
		case BLK_ZONE_TYPE_SEQWRITE_REQ:
			z->type = ZBD_ZONE_TYPE_SWR;
			break;
		case BLK_ZONE_TYPE_SEQWRITE_PREF:
			z->type = ZBD_ZONE_TYPE_SWP;
			break;
		default:
			td_verror(td, errno, "invalid zone type");
			log_err("zbd_zone_mgmt_report %s: invalid type %d for zone at sector %llu.\n",
				f->file_name, zone_log->zone_type, (unsigned long long)(offset >> 9));
			ret = -EIO;
			goto out;
		}

		switch (zone_log->zone_state) {
		case NVME_ZONE_EMPTY:
			z->cond = ZBD_ZONE_COND_EMPTY;
			break;
		case NVME_ZONE_IMPLICITLY_OPENED:
			z->cond = ZBD_ZONE_COND_IMP_OPEN;
			break;
		case NVME_ZONE_EXPLICITLY_OPENED:
			z->cond = ZBD_ZONE_COND_EXP_OPEN;
			break;
		case NVME_ZONE_CLOSED:
			z->cond = ZBD_ZONE_COND_CLOSED;
			break;
		case NVME_ZONE_FULL:
			z->cond = ZBD_ZONE_COND_FULL;
			break;
		case NVME_ZONE_READONLY:
		case NVME_ZONE_OFFLINE:
		default:
			/* Treat all these conditions as offline (don't use!) */
			z->cond = ZBD_ZONE_COND_OFFLINE;
			break;
		}
		buff += zone_info_sz;
	}

	ret = nr_zones;
out:
	free((void*)hdr);
	close(fd);
	return ret;
}

int zbd_create_zone_data(struct thread_data *td, unsigned int nr_zones)
{
	struct nvme_zone_report_header	hdr;
	struct nvme_zone_log zone_log;
	unsigned int i;
	int fd;
	char file_name[20];
	sprintf(file_name, "namespace_%d.bin",nr_zones);

	fd = open(file_name, O_CREAT | O_WRONLY, S_IWUSR);
	if (fd < 0) {
		return -errno;
	}

	hdr.nr_zones = nr_zones;
	if (write(fd, (void*)&hdr, sizeof(hdr)) < sizeof(zone_log)) {
		close (fd);
		return -1;
	}
	zone_log.capacity = 0x43500;
	zone_log.wp = 0x00000;
	zone_log.slba = 0x00000;
	zone_log.zone_type = 2;
	zone_log.zone_state = NVME_ZONE_EMPTY;

	dprint(FD_ZBD, "zbd_zone_mgmt_report: num zones = %d, id = %d\n", nr_zones, td->thread_number);
	for (i = 0; i < nr_zones; i++) {

		if (write(fd, (void*)&zone_log, sizeof(zone_log)) < sizeof(zone_log)) {
			close (fd);
			return -1;
		}

		zone_log.slba += 0x80000;
		zone_log.wp = zone_log.slba;

	}

	return nr_zones;
}

bool zbd_update_zone_data(struct thread_data *td, uint64_t wp, uint8_t state, unsigned int zone)
{
//	struct nvme_zone_report_headerhdr;
	struct nvme_zone_log zone_log;
	int fd, ret;
	char file_name[20];
	off_t offset = sizeof(struct nvme_zone_report_header) + (zone * sizeof(struct nvme_zone_log));

	sprintf(file_name, "namespace_%d.bin",td->o.num_simulated_zones);

	log_err("zbd_update_zone_data: zone = %u, id = %d, wp = 0x%lX, state = %u, offset = %lu\n",
			zone, td->thread_number, wp, state, offset);

	fd = open(file_name, O_RDWR, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		return false;
	}

	lseek(fd, offset, SEEK_SET);
	ret = read(fd, (void*)&zone_log, sizeof(zone_log));
	if (ret < sizeof(zone_log)) {
		close(fd);
		return false;
	}
	lseek(fd, offset, SEEK_SET);
	zone_log.wp = wp;
	zone_log.zone_state = state;
	if (write(fd, (void*)&zone_log, sizeof(zone_log)) < sizeof(zone_log)) {
		close (fd);
		return false;
	}

	return true;
}

int blkzoned_reset_wp(struct thread_data *td, struct fio_file *f,
		      uint64_t offset, uint64_t length)
{
	struct blk_zone_range zr = {
		.sector         = offset >> 9,
		.nr_sectors     = length >> 9,
	};
	int fd, ret = 0;

	/* If the file is not yet opened, open it for this function. */
	fd = f->fd;
	if (fd < 0) {
		fd = open(f->file_name, O_RDWR | O_LARGEFILE);
		if (fd < 0)
			return -errno;
	}

	if (ioctl(fd, BLKRESETZONE, &zr) < 0)
		ret = -errno;

	if (f->fd < 0)
		close(fd);

	return ret;
}


int zbd_get_open_count(int fd, int nsid, int implicit)
{
	int ret;
	int log_len;
	struct nvme_zone_report_header * report_header;
	void * buff;
	struct nvme_passthru_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));

	log_len = sizeof(struct nvme_zone_log) +
		sizeof(struct nvme_zone_report_header);

	buff = malloc(log_len);
	if (!buff) {
		return -1;
	}

	cmd.opcode     = nvme_cmd_zone_mgmt_recv;
	cmd.nsid       = nsid;
	cmd.cdw10      = 0;
	cmd.cdw11      = 0;
	cmd.cdw13      = (2 + implicit) << 8;
	cmd.addr       = (__u64)(uintptr_t)buff;
	cmd.data_len   = log_len;

	ret = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
	if (ret > 0) {
		perror("zbd_get_open_count failed ioctl returned:");
		dprint(FD_ZBD, "zbd_get_open_count failed nsid = %d\n", nsid);
		return -1;
	}

	report_header = (struct nvme_zone_report_header *)buff;
	return report_header->nr_zones;

}

bool zbd_identify_ns(struct thread_data *td, struct fio_file *f, void *ns, void *ns_zns, int nsid)
{
	int fd, ret = 0;
	struct nvme_passthru_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));

	if (td->o.num_simulated_zones == 0) {

		fd = open(f->file_name, O_RDONLY | O_LARGEFILE);
		if (fd < 0) {
			ret = -errno;
			goto close;
		}

		cmd.opcode     = 6;				//nvme_admin_identify
		cmd.nsid       = nsid;
		cmd.cdw10      = 5;
		cmd.cdw11      = 0;
		cmd.addr       = (__u64)(uintptr_t)ns;
		cmd.data_len   = 4096; //sizeof(struct nvme_id_ns_zns);

		ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
		if (ret > 0) {
			perror("ioctl returned:");
		}
		cmd.cdw11      = 2 << 24;
		cmd.addr       = (__u64)(uintptr_t)ns_zns;
		ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
		if (ret > 0) {
			perror("zbd_identify_ns: ioctl returned:");

		}

	close:
		close(fd);
		if (ret != 0)
			return false;
	} else {
//		(struct nvme_id_ns *)ns->
		((struct nvme_id_ns_zns_2 *)ns_zns)->mar = 13;
		((struct nvme_id_ns_zns_2 *)ns_zns)->zrwas = (uint16_t)0x100000;
	}

	return true;
}

int zbd_get_nsid(struct fio_file *f)
{
	static struct stat nvme_stat;
	int fd, err = 0;

	fd = open(f->file_name, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		err = -errno;
		goto close;
	}

	err = fstat(fd, &nvme_stat);

	if (err < 0)
		goto close;

	if (!S_ISBLK(nvme_stat.st_mode)) {
		log_err("Error: requesting namespace-id from non-block device\n");
		err = ENOTBLK;
		goto close;
	}

	err = ioctl(fd, NVME_IOCTL_ID);

close:
	close(fd);

	return err;

}

bool zbd_zone_reset(struct thread_data *td, struct fio_file *f, uint64_t slba, bool all_zones, int nsid)
{
	int fd, ret;
	bool reply = true;
	struct buf_output out;
	struct nvme_passthru_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));

	fd = f->fd;
	if (fd < 0) {
		fd = open(f->file_name, O_RDWR | O_LARGEFILE);
		if (fd < 0)
			return false;
	}

	dprint(FD_ZBD, "zbd_zone_reset: filename = %s slba = 0x%lX, nsid = %d \n", f->file_name, slba, nsid);

	cmd.opcode     = nvme_cmd_zone_mgmt_send;
	cmd.nsid       = nsid;
	cmd.cdw10      = slba & 0xffffffff;
	cmd.cdw11      = slba >> 32;
	if (all_zones)
		cmd.cdw13      = (1 << NVME_ZONE_MGMT_SEND_SELECT_ALL) | NVME_ZONE_ACTION_RESET;
	else
		cmd.cdw13      = NVME_ZONE_ACTION_RESET;
	cmd.addr       = (__u64)(uintptr_t)NULL;
	cmd.data_len   = 0;

	if (all_zones) {
		buf_output_init(&out);
		__log_buf(&out, "Resetting all zones\n");
		log_info_buf(out.buf, out.buflen);
	}
	ret = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);

	if (ret > 0) {
		perror("zbd_zone_reset failed- ioctl returned: ");
		dprint(FD_ZBD, "zbd_zone_reset: ret = %d \n", ret);
		reply =  false;
	}

	if (all_zones)
		buf_output_free(&out);

	close(fd);

	return reply;
}

int zbd_issue_finish(struct thread_data *td, struct fio_file *f,
		      uint64_t offset, uint64_t length)
{

	struct blk_zone_range zr = {
		.sector         = offset >> 9,
		.nr_sectors     = length >> 9,
	};

	if (ioctl(f->fd, BLKFINISHZONE, &zr) < 0)
		return -errno;

	return 0;
}

bool zbd_issue_commit_zone(const struct fio_file *f, uint32_t zone_idx, uint64_t lba, uint64_t slba, int nsid)
{
	int ret;
	uint32_t cdw13 = 0;
	struct nvme_passthru_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cdw13 = NVME_ZONE_ACTION_COMMIT;

	cmd.opcode     = 0x79;				//nvme_cmd_zone_mgmt_send
	cmd.nsid       = nsid;
	cmd.cdw10      = lba & 0xffffffff;
	cmd.cdw11      = lba >> 32;
	cmd.cdw13      = cdw13;
	cmd.addr       = (__u64)(uintptr_t)NULL;
	cmd.data_len   = 0;

	dprint(FD_ZBD, "Issuing commit_zone to zone %d, slba %lu, nsid %d, lba = %lu\n", zone_idx,
						slba, nsid, lba);
	ret = ioctl(f->fd, NVME_IOCTL_IO_CMD, &cmd);
	if (ret > 0) {
		perror("zbd_issue_commit_zone failed - ioctl returned:");
		dprint(FD_ZBD, "zbd_issue_commit_zone failed: slba = 0x%lX \n", slba);
		return false;
	}
	return true;
}

bool zbd_issue_exp_open_zrwa(const struct fio_file *f, uint32_t zone_idx,
		uint64_t slba , uint32_t nsid)
{
	int ret;
	uint32_t cdw13 = 0;
	uint32_t zrwaa = 1;
	struct nvme_passthru_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));

	cdw13 = NVME_ZONE_ACTION_OPEN; //Open zone explicitly
	cdw13 |= zrwaa << NVME_ZONE_MGMT_SEND_ZRWAA; //Set this bit to indicate alloc zrwa

	cmd.opcode     = 0x79;				//nvme_cmd_zone_mgmt_send
	cmd.nsid       = nsid;
	cmd.cdw10      = slba & 0xffffffff;
	cmd.cdw11      = slba >> 32;
	cmd.cdw13      = cdw13;
	cmd.addr       = (__u64)(uintptr_t)NULL;
	cmd.data_len   = 0;

	dprint(FD_ZBD, "Issuing Exp-Open to zone %d, slba 0x%lX, nsid %d\n", zone_idx,
						slba, nsid);
	ret = ioctl(f->fd, NVME_IOCTL_IO_CMD, &cmd);
	if (ret > 0) {
		perror("zbd_issue_exp_open_zrwa failed - ioctl returned:");
		dprint(FD_ZBD, "zbd_issue_exp_open_zrwa failed: slba = 0x%lX \n", slba);
		return false;
	}
	return true;
}

