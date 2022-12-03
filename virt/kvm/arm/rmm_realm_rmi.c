#include <linux/kvm_host.h>

#define R_PAGE_SHIFT	12
#define R_PAGE_SIZE	1 << R_PAGE_SHIFT

// The following are RMI implementation

u64 rmi_version(){
    return REALM_SUCCESS;
}

u64 rmi_features(){
    return REALM_SUCCESS;
}

u64 rmi_granule_delegate(u64 addr){
    return REALM_SUCCESS;
}

// The following are realm management implementation

u64 realm_create(realm *realm){
    u64 ret;

    // TODO: change the state of realm to REALM_STATE_NULL
	realm->state = REALM_STATE_NULL;

    // TODO: set the range of reserved memory for realm image
    realm->par_size = REALM_MAX_LOAD_IMG_SIZE;

    // TODO: allocate reserved memory for realm image

    // TODO: allocate and delegate granule for rd (realm descriptor)

    // TODO: allocate and delegate granule for rtt (realm translation table)

    // TODO: allocate memory for parameters

    // TODO: fill up parameters

    // TODO: create realm using rmi_realm_create, requiring rd and parameters

    // TODO: deal with realm aux

    // TODO: change the state of realm to REALM_STATE_NEW

    // TODO: free unuse var parameter

    return REALM_SUCCESS;
}