#include <linux/kvm_host.h>

#define R_PAGE_SHIFT	12U
#define R_PAGE_SIZE	1U << R_PAGE_SHIFT

// The following are RMI implementation

u64 rmi_version(){
    return REALM_SUCCESS;
}

u64 rmi_features(){
    return REALM_SUCCESS;
}

u64 rmi_granule_delegate(u64 addr){
    kvm_info("RMI GRANULE DELEGATE: %lx\n", addr);
    // TODO: implement granule delegate smc

    return REALM_SUCCESS;
}

u64 rmi_granule_undelegate(u64 addr){
    kvm_info("RMI GRANULE UNDELEGATE: %lx\n", addr);
    // TODO: implement granule delegate smc

    return REALM_SUCCESS;
}

u64 rmi_realm_create(u64 rd, u64 params_ptr){
    kvm_info("RMI REALM CREATE: rd: %lx, params_ptr: %lx\n", rd, params_ptr);
    // TODO: implement realm create smc

    return REALM_SUCCESS;
}

u64 rmi_realm_destroy(u64 rd){
    kvm_info("RMI REALM DESTROY: rd: %lx\n", rd);
    // TODO: implement realm destroy smc

    return REALM_SUCCESS;
}

u64 rmi_rec_aux_count(u64 rd, u64 *aux_count){
    kvm_info("RMI REC AUX COUNT: rd: %lx aux_count: %lx\n", rd, aux_count);
    // TODO: implement rec aux count smc

    return REALM_SUCCESS;
}

//----------------------------------------------------------------------------------

// The following are realm management implementation

u64 realm_create(realm *realm_vm){
    rmi_realm_params *params;
    u64 ret;

    // change the state of realm to REALM_STATE_NULL
	realm_vm->state = REALM_STATE_NULL;

    // set the range of reserved memory for realm image
    realm_vm->par_size = REALM_MAX_LOAD_IMG_SIZE;

    // allocate reserved memory for realm image
    realm_vm->par_base = (u64)kmalloc(realm_vm->par_size, GFP_KERNEL);
    if (realm_vm->par_base == NULL){
        kvm_info("page_alloc failed, base=0x%lx, size=0x%lx\n",
			  realm_vm->par_base, realm_vm->par_size);
        return REALM_ERROR;
    }

    // allocate and delegate granule for rd (realm descriptor)
    realm_vm->rd = (u64)kmalloc(R_PAGE_SIZE, GFP_KERNEL);
    if (realm_vm->rd == NULL) {
		kvm_info("Failed to allocate memory for rd\n");
		goto err_free_par;
	} else {
		ret = rmi_granule_delegate(realm_vm->rd);
		if (ret != RMI_SUCCESS) {
			kvm_info("rd delegation failed, rd=0x%lx, ret=0x%lx\n",
					realm_vm->rd, ret);
			goto err_free_rd;
		}
	}

    // allocate and delegate granule for rtt (realm translation table)
    realm_vm->rtt_addr = (u64)kmalloc(R_PAGE_SIZE, GFP_KERNEL);
	if (realm_vm->rtt_addr == NULL) {
		kvm_info("Failed to allocate memory for rtt_addr\n");
		goto err_undelegate_rd;
	} else {
		ret = rmi_granule_delegate(realm_vm->rtt_addr);
		if (ret != RMI_SUCCESS) {
			kvm_info("rtt delegation failed, rtt_addr=0x%lx, ret=0x%lx\n",
					realm_vm->rtt_addr, ret);
			goto err_free_rtt;
		}
	}

    // TODO: allocate memory for parameters
    params = (rmi_realm_params*)kmalloc(R_PAGE_SIZE, GFP_KERNEL);
    if (params == NULL) {
		kvm_info("Failed to allocate memory for params\n");
		goto err_undelegate_rtt;
	}

    // fill up parameters
	params->features_0 = realm_vm->rmm_feat_reg0;
	params->rtt_level_start = 0L;
	params->rtt_num_start = 1U;
	params->rtt_base = realm_vm->rtt_addr;
    // TODO: replace it with a variable
	params->vmid = 1U;
	params->hash_algo = RMI_HASH_SHA_256;

    // create realm using RMI, requiring rd and parameters
    ret = rmi_realm_create(realm_vm->rd, (u64)params);
	if (ret != RMI_SUCCESS) {
		kvm_info("Realm create failed, rd=0x%lx, ret=0x%lx\n",
			 realm_vm->rd, ret);
		goto err_free_params;
	}

    // deal with realm aux
    ret = rmi_rec_aux_count(realm_vm->rd, &realm_vm->num_aux);
	if (ret != RMI_SUCCESS) {
		kvm_info("rmi_rec_aux_count failed, rd=0x%lx, ret=0x%lx\n",
			 realm_vm->rd, ret);
		rmi_realm_destroy(realm_vm->rd);
		goto err_free_params;
	}

    // change the state of realm to REALM_STATE_NEW
    realm_vm->state = REALM_STATE_NEW;

    // free unuse var parameter
    kfree((u64)params);
    return REALM_SUCCESS;

err_free_params:
	kfree((u64)params);

err_undelegate_rtt:
	ret = rmi_granule_undelegate(realm_vm->rtt_addr);
	if (ret != RMI_SUCCESS) {
		kvm_info("rtt undelegation failed, rtt_addr=0x%lx, ret=0x%lx\n",
		realm_vm->rtt_addr, ret);
	}

err_free_rtt:
	kfree(realm_vm->rtt_addr);

err_undelegate_rd:
	ret = rmi_granule_undelegate(realm_vm->rd);
	if (ret != RMI_SUCCESS) {
		kvm_info("rd undelegation failed, rd=0x%lx, ret=0x%lx\n", 
        realm_vm->rd, ret);
	}

err_free_rd:
	kfree(realm_vm->rd);

err_free_par:
	kfree(realm_vm->par_base);

    return REALM_ERROR;
}