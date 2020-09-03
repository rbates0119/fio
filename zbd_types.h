/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 */
#ifndef FIO_ZBD_TYPES_H
#define FIO_ZBD_TYPES_H

#include <inttypes.h>

//#define ZBD_MAX_OPEN_ZONES	4096

/*
 * Zoned block device models.
 */
enum zbd_zoned_model {
	ZBD_IGNORE,		/* Ignore file */
	ZBD_NONE,		/* Regular block device */
	ZBD_HOST_AWARE,		/* Host-aware zoned block device */
	ZBD_HOST_MANAGED,	/* Host-managed zoned block device */
};

/*
 * Zone types.
 */
enum zbd_zone_type {
	ZBD_ZONE_TYPE_CNV	= 0x1,	/* Conventional */
	ZBD_ZONE_TYPE_SWR	= 0x2,	/* Sequential write required */
	ZBD_ZONE_TYPE_SWP	= 0x3,	/* Sequential write preferred */
};

/*
 * Zone conditions.
 */
enum zbd_zone_cond {
        ZBD_ZONE_COND_NOT_WP    = 0x0,
        ZBD_ZONE_COND_EMPTY     = 0x1,
        ZBD_ZONE_COND_IMP_OPEN  = 0x2,
        ZBD_ZONE_COND_EXP_OPEN  = 0x3,
        ZBD_ZONE_COND_CLOSED    = 0x4,
        ZBD_ZONE_COND_READONLY  = 0xD,
        ZBD_ZONE_COND_FULL      = 0xE,
        ZBD_ZONE_COND_OFFLINE   = 0xF,
};

/*
 * Zone descriptor.
 */
struct zbd_zone {
	uint64_t		start;
	uint64_t		wp;
	uint64_t		len;
	uint64_t        capacity;
	enum zbd_zone_type	type;
	enum zbd_zone_cond	cond;
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

struct nvme_zone_log {
        __u8            zone_type;
        __u8            zone_state;
        __u8            zone_attrs;
        __u8            __res[5];
        __le64          capacity;
        __le64          slba;
        __le64          wp;
        __u8            __res2[32];
};

struct nvme_zone_report_header {
	__u64           nr_zones;
	__u8            __res[56];
};

enum nvme_opcode {
	nvme_cmd_flush		= 0x00,
	nvme_cmd_write		= 0x01,
	nvme_cmd_read		= 0x02,
	nvme_cmd_write_uncor	= 0x04,
	nvme_cmd_compare	= 0x05,
	nvme_cmd_write_zeroes	= 0x08,
	nvme_cmd_dsm		= 0x09,
	nvme_cmd_verify		= 0x0c,
	nvme_cmd_resv_register	= 0x0d,
	nvme_cmd_resv_report	= 0x0e,
	nvme_cmd_resv_acquire	= 0x11,
	nvme_cmd_resv_release	= 0x15,
	nvme_cmd_zone_mgmt_send	= 0x79,
	nvme_cmd_zone_mgmt_recv	= 0x7A,
	nvme_cmd_zone_append	= 0x7d,
};

enum nvme_zone_management_action_send_flags {
	NVME_ZONE_MGMT_SEND_SELECT_ALL		= 8,
	NVME_ZONE_MGMT_SEND_ZRWAA		= 9,
};

enum nvme_zone_action {
	NVME_ZONE_ACTION_CLOSE			= 0x1,
	NVME_ZONE_ACTION_FINISH			= 0x2,
	NVME_ZONE_ACTION_OPEN			= 0x3,
	NVME_ZONE_ACTION_RESET			= 0x4,
	NVME_ZONE_ACTION_OFFLINE		= 0x5,
	NVME_ZONE_ACTION_SET_EXTENSION		= 0x10,
	NVME_ZONE_ACTION_COMMIT_ZONE		= 0x11,
};

#endif /* FIO_ZBD_TYPES_H */
