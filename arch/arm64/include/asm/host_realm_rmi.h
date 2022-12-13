#ifndef HOST_REALM_RMI_H
#define HOST_REALM_RMI_H

#include <asm/smc_helper.h>

#define REALM_SUCCESS			0U
#define REALM_ERROR			1U
#define REALM_MAX_LOAD_IMG_SIZE 0x100000U

/* Maximum number of auxiliary granules required for a REC */
#define MAX_REC_AUX_GRANULES		16U
#define REC_PARAMS_AUX_GRANULES		16U
#define REC_EXIT_NR_GPRS		31U

/* Size of Realm Personalization Value */
#define RPV_SIZE			64U

/* RmiRealmMeasurementAlgorithm types */
#define RMI_HASH_SHA_256		0U
#define RMI_HASH_SHA_512		1U

/* RmiRecEmulatedMmio types */
#define RMI_NOT_EMULATED_MMIO		0U
#define RMI_EMULATED_MMIO		1U

/*
 * RmiRecExitReason represents the reason for a REC exit.
 * This is returned to NS hosts via RMI_REC_ENTER::run_ptr.
 */
#define RMI_EXIT_SYNC			0U
#define RMI_EXIT_IRQ			1U
#define RMI_EXIT_FIQ			2U
#define RMI_EXIT_PSCI			3U
#define RMI_EXIT_RIPAS_CHANGE		4U
#define RMI_EXIT_HOST_CALL		5U
#define RMI_EXIT_SERROR			6U
#define RMI_EXIT_INVALID		0xFFFFFU

/* RmiRecRunnable types */
#define RMI_NOT_RUNNABLE		0U
#define RMI_RUNNABLE			1U

/* RttEntryState: represents the state of an RTTE */
#define RMI_UNASSIGNED			0U
#define RMI_DESTROYED			1U
#define RMI_ASSIGNED			2U
#define RMI_TABLE			3U
#define RMI_VALID_NS			4U

/*
 * Defines member of structure and reserves space
 * for the next member with specified offset.
 */
#define SET_MEMBER(member, start, end)	\
	union {				\
		member;			\
		unsigned char reserved##end[end - start]; \
	}


typedef enum {
	/*
	 * Command completed successfully.
	 *
	 * index is zero.
	 */
	RMI_SUCCESS = 0,
	/*
	 * The value of a command input value caused the command to fail.
	 *
	 * index is zero.
	 */
	RMI_ERROR_INPUT = 1,
	/*
	 * An attribute of a Realm does not match the expected value.
	 *
	 * index varies between usages.
	 */
	RMI_ERROR_REALM = 2,
	/*
	 * An attribute of a REC does not match the expected value.
	 *
	 * index is zero.
	 */
	RMI_ERROR_REC = 3,
	/*
	 * An RTT walk terminated before reaching the target RTT level,
	 * or reached an RTTE with an unexpected value.
	 *
	 * index: RTT level at which the walk terminated
	 */
	RMI_ERROR_RTT = 4,
	/*
	 * An operation cannot be completed because a resource is in use.
	 *
	 * index is zero.
	 */
	RMI_ERROR_IN_USE = 5,
	RMI_ERROR_COUNT
} status_t;

#define RMI_RETURN_STATUS(ret)		((ret) & 0xFF)
#define RMI_RETURN_INDEX(ret)		(((ret) >> 8U) & 0xFF)
#define RTT_MAX_LEVEL			3U
#define ALIGN_DOWN(x, a)		((uint64_t)(x) & ~(((uint64_t)(a)) - 1ULL))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a)-1U)) == 0U)
// TODO: LEVEL SHIFT HAS NOT IMPLEMENTED: origin using XLAT_ADDR_SHIFT(l)
// cuurently, I use 28 to replace it.
#define RTT_LEVEL_SHIFT(l)		30U
#define RTT_L2_BLOCK_SIZE		(1UL << RTT_LEVEL_SHIFT(2U))

#define REC_CREATE_NR_GPRS		8U
#define REC_GIC_NUM_LRS			16U

enum {
    // rmi between kvm and rmm
	SMC_RMM_VERSION,
    SMC_RMM_FEATURES,
    SMC_RMM_GRANULE_DELEGATE,
    SMC_RMM_GRANULE_UNDELEGATE,
    SMC_RMM_REALM_CREATE,
    SMC_RMM_REALM_DESTROY,
    SMC_RMM_REALM_ACTIVATE,
    SMC_RMM_REC_CREATE,
    SMC_RMM_REC_DESTROY,
    SMC_RMM_REC_ENTER,
    SMC_RMM_DATA_CREATE,
    SMC_RMM_DATA_CREATE_UNKNOWN,
    SMC_RMM_DATA_DESTROY,
    SMC_RMM_RTT_CREATE,
	SMC_RMM_RTT_DESTROY,
    SMC_RMM_RTT_FOLD,
    SMC_RMM_RTT_MAP_UNPROTECTED,
    SMC_RMM_RTT_UNMAP_UNPROTECTED,
    SMC_RMM_RTT_READ_ENTRY,
    SMC_RMM_PSCI_COMPLETE,
    SMC_RMM_REC_AUX_COUNT,
    SMC_RMM_RTT_INIT_RIPAS,
    SMC_RMM_RTT_SET_RIPAS
};

typedef struct {
	/* Realm feature register 0 */
	SET_MEMBER(u64 features_0, 0, 0x100);		/* Offset 0 */
	/* Measurement algorithm */
	SET_MEMBER(unsigned char hash_algo, 0x100, 0x400);	/* 0x100 */
	/* Realm Personalization Value */
	SET_MEMBER(unsigned char rpv[RPV_SIZE], 0x400, 0x800);	/* 0x400 */
	SET_MEMBER(struct {
		/* Virtual Machine Identifier */
		unsigned short vmid;				/* 0x800 */
		/* Realm Translation Table base */
		u64 rtt_base;				/* 0x808 */
		/* RTT starting level */
		long rtt_level_start;				/* 0x810 */
		/* Number of starting level RTTs */
		unsigned int rtt_num_start;			/* 0x818 */
	}, 0x800, 0x1000);
} rmi_realm_params;

typedef struct {
	/* Flags */
	SET_MEMBER(u64 flags, 0, 0x100);		/* Offset 0 */
	/* MPIDR of the REC */
	SET_MEMBER(u64 mpidr, 0x100, 0x200);		/* 0x100 */
	/* Program counter */
	SET_MEMBER(u64 pc, 0x200, 0x300);		/* 0x200 */
	/* General-purpose registers */
	SET_MEMBER(u64 gprs[REC_CREATE_NR_GPRS], 0x300, 0x800); /* 0x300 */
	SET_MEMBER(struct {
		/* Number of auxiliary Granules */
		u64 num_aux;				/* 0x800 */
		/* Addresses of auxiliary Granules */
		u64 aux[MAX_REC_AUX_GRANULES];		/* 0x808 */
	}, 0x800, 0x1000);
} rmi_rec_params;

/*
 * Structure contains data passed from the Host to the RMM on REC entry
 */
typedef struct {
	/* Flags */
	SET_MEMBER(u64 flags, 0, 0x200);		/* Offset 0 */
	/* General-purpose registers */
	SET_MEMBER(u64 gprs[REC_EXIT_NR_GPRS], 0x200, 0x300); /* 0x200 */
	SET_MEMBER(struct {
		/* GICv3 Hypervisor Control Register */
		u64 gicv3_hcr;				/* 0x300 */
		/* GICv3 List Registers */
		u64 gicv3_lrs[REC_GIC_NUM_LRS];	/* 0x308 */
	}, 0x300, 0x800);
} rmi_rec_entry;

/*
 * Structure contains data passed from the RMM to the Host on REC exit
 */
typedef struct {
	/* Exit reason */
	SET_MEMBER(u64 exit_reason, 0, 0x100);/* Offset 0 */
	SET_MEMBER(struct {
		/* Exception Syndrome Register */
		u64 esr;				/* 0x100 */
		/* Fault Address Register */
		u64 far;				/* 0x108 */
		/* Hypervisor IPA Fault Address register */
		u64 hpfar;				/* 0x110 */
	}, 0x100, 0x200);
	/* General-purpose registers */
	SET_MEMBER(u64 gprs[REC_EXIT_NR_GPRS], 0x200, 0x300); /* 0x200 */
	SET_MEMBER(struct {
		/* GICv3 Hypervisor Control Register */
		u64 gicv3_hcr;				/* 0x300 */
		/* GICv3 List Registers */
		u64 gicv3_lrs[REC_GIC_NUM_LRS];	/* 0x308 */
		/* GICv3 Maintenance Interrupt State Register */
		u64 gicv3_misr;			/* 0x388 */
		/* GICv3 Virtual Machine Control Register */
		u64 gicv3_vmcr;			/* 0x390 */
	}, 0x300, 0x400);
	SET_MEMBER(struct {
		/* Counter-timer Physical Timer Control Register */
		u64 cntp_ctl;				/* 0x400 */
		/* Counter-timer Physical Timer CompareValue Register */
		u64 cntp_cval;				/* 0x408 */
		/* Counter-timer Virtual Timer Control Register */
		u64 cntv_ctl;				/* 0x410 */
		/* Counter-timer Virtual Timer CompareValue Register */
		u64 cntv_cval;				/* 0x418 */
	}, 0x400, 0x500);
	SET_MEMBER(struct {
		/* Base address of pending RIPAS change */
		u64 ripas_base;			/* 0x500 */
		/* Size of pending RIPAS change */
		u64 ripas_size;			/* 0x508 */
		/* RIPAS value of pending RIPAS change */
		unsigned char ripas_value;			/* 0x510 */
	}, 0x500, 0x600);
	/* Host call immediate value */
	SET_MEMBER(unsigned int imm, 0x600, 0x800);		/* 0x600 */
} rmi_rec_exit;

/*
 * Structure contains shared information between RMM and Host
 * during REC entry and REC exit.
 */
typedef struct {
	/* Entry information */
	SET_MEMBER(rmi_rec_entry entry, 0, 0x800);	/* Offset 0 */
	/* Exit information */
	SET_MEMBER(rmi_rec_exit exit, 0x800, 0x1000);	/* 0x800 */
} rmi_rec_run;

typedef struct {
	uint64_t walk_level;
	uint64_t out_addr;
	int state;
} rtt_entry;

enum realm_state {
	REALM_STATE_NULL,
	REALM_STATE_NEW,
	REALM_STATE_ACTIVE,
	REALM_STATE_SYSTEM_OFF
};

typedef struct {
	u64 par_base;
	u64 par_size;
	u64 rd;
	u64 rtt_addr;
	u64 rec;
	u64 run;
	u64 num_aux;
	u64 rmm_feat_reg0;
	u64 ipa_ns_buffer;
	u64 ns_buffer_size;
	u64 aux_pages[REC_PARAMS_AUX_GRANULES];
	enum realm_state state;
} realm;

/* The following are the rmi APIs */
u64 rmi_features(u64 index, u64 *features);
u64 rmi_version(void);
u64 rmi_granule_delegate(u64 addr);
u64 rmi_granule_undelegate(u64 addr);
u64 rmi_data_create(bool unknown, u64 data, u64 rd, u64 map_addr, u64 src);
u64 rmi_data_destroy(u64 rd, u64 map_addr);
u64 rmi_realm_create(u64 rd, u64 params_ptr);
u64 rmi_realm_destroy(u64 rd);
u64 rmi_realm_activate(u64 rd);
u64 rmi_rec_create(u64 rec, u64 rd, u64 params_ptr);
u64 rmi_rec_destroy(u64 rec);
u64 rmi_rtt_create(u64 rtt, u64 rd, u64 map_addr, u64 level);
u64 rmi_rtt_destroy(u64 rtt, u64 rd, u64 map_addr, u64 level);
u64 rmi_rec_aux_count(u64 rd, u64 *aux_count);


/* The following are encapsulated APIs of RMIs for realm management */
u64 realm_create(realm *realm);
u64 realm_map_protected_data_unknown(realm *realm, u64 target_pa,u64 map_size);
u64 realm_map_payload_image(realm *realm, u64 realm_payload_adr);
u64 realm_map_ns_shared(realm *realm, u64 ns_shared_mem_adr,
			u64 ns_shared_mem_size);
u64 realm_rec_create(realm *realm);
u64 realm_activate(realm *realm);
u64 realm_destroy(realm *realm);
u64 realm_rec_enter(realm *realm, u64 *exit_reason,
		    unsigned int *test_result);
u64 realm_init_ipa_state(realm *realm, u64 level, u64 start,
			 uint64_t end);
/* The above are encapsulated APIs of RMIs for realm management  */

#endif /* HOST_REALM_RMI_H */