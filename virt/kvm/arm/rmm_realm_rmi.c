#include <linux/kvm_host.h>

#include <asm/smc_helper.h>
#include <asm/kvm_mmu.h>
#include <asm/memory.h>

#define R_PAGE_SHIFT	12U
#define R_PAGE_SIZE	1U << R_PAGE_SHIFT

//----------------------------------------------------------------------------------
smc_ret_values tftf_smc(const smc_args *args)
{
	return (smc_ret_values) {REALM_SUCCESS, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL};
}


//----------------------------------------------------------------------------------

// The following are RMI implementation

u64 rmi_version(){
	return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_VERSION,
			0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL}))).ret0;
}

u64 rmi_features(u64 index, u64 *features){
	kvm_info("RMI QUERY FEATURES\n");
	smc_ret_values rets;
	rets = tftf_smc(&(smc_args) {SMC_RMM_FEATURES, index, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL});
	*features = rets.ret1;
    return rets.ret0;
}

u64 rmi_granule_delegate(u64 addr){
	u64 addr_pa = virt_to_phys(addr);
    kvm_info("RMI GRANULE DELEGATE: addr: %lx\n", addr);
	kvm_info("RMI GRANULE DELEGATE: addr_pa: %lx\n", addr_pa);
    
    return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_GRANULE_DELEGATE,
			addr, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL}))).ret0;
}

u64 rmi_granule_undelegate(u64 addr){
	u64 addr_pa = virt_to_phys(addr);
    kvm_info("RMI GRANULE UNDELEGATE: addr: %lx\n", addr);
	kvm_info("RMI GRANULE UNDELEGATE: addr_pa: %lx\n", addr_pa);

	return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_GRANULE_UNDELEGATE,
			addr, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL}))).ret0;
}

u64 rmi_realm_activate(u64 rd){
	u64 rd_pa = virt_to_phys(rd);
	kvm_info("RMI REALM ACTIVATE: rd: %lx\n", rd);
	kvm_info("RMI REALM ACTIVATE: rd_pa: %lx\n", rd_pa);
	
	return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_REALM_ACTIVATE,
		rd, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL}))).ret0;
}

u64 rmi_realm_create(u64 rd, u64 params_ptr){
	u64 rd_pa = virt_to_phys(rd);
	u64 params_pa = virt_to_phys(params_ptr);
    kvm_info("RMI REALM CREATE: rd: %lx, params_ptr: %lx\n", rd, params_ptr);
	kvm_info("RMI REALM CREATE: rd_pa: %lx, params_pa: %lx\n", rd_pa, params_pa);
    
	return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_REALM_CREATE,
		rd, params_ptr, 0UL, 0UL, 0UL, 0UL, 0UL}))).ret0;
}

u64 rmi_realm_destroy(u64 rd){
	u64 rd_pa = virt_to_phys(rd);
    kvm_info("RMI REALM DESTROY: rd: %lx\n", rd);
	kvm_info("RMI REALM DESTROY: rd_pa: %lx\n", rd_pa);
    
	return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_REALM_DESTROY,
		rd, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL}))).ret0;
}


u64 rmi_data_create(bool unknown, u64 data, u64 rd, u64 map_addr, u64 src){
	u64 rd_pa = virt_to_phys(rd);
	u64 map_addr_pa = virt_to_phys(map_addr);
	u64 src_pa = virt_to_phys(src);
	kvm_info("RMI DATA CREATE: unknown: %lx, data: %lx, rd: %lx, map_addr: %lx, src: %lx\n", unknown, data, rd, map_addr, src);
	kvm_info("RMI DATA CREATE: rd_pa: %lx, map_addr_pa: %lx, src_pa: %lx\n", rd_pa, map_addr_pa, src_pa);

	if (unknown) {
		return ((smc_ret_values)(tftf_smc(&(smc_args)
				{SMC_RMM_DATA_CREATE_UNKNOWN, data, rd, map_addr,
			0UL, 0UL, 0UL, 0UL}))).ret0;
	} else {
		return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_DATA_CREATE,
			data, rd, map_addr, src, 0UL, 0UL, 0UL}))).ret0;
	}
}

u64 rmi_data_destroy(u64 rd, u64 map_addr){
	u64 rd_pa = virt_to_phys(rd);
	u64 map_addr_pa = virt_to_phys(map_addr);
	kvm_info("RMI DATA DESTROY: rd: %lx, map_addr: %lx\n", rd, map_addr);
	kvm_info("RMI DATA DESTROY: rd_pa: %lx, map_addr_pa: %lx\n", rd_pa, map_addr_pa);
	
	return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_DATA_DESTROY,
		rd, map_addr, 0UL, 0UL, 0UL, 0UL, 0UL}))).ret0;
}

u64 rmi_rec_create(u64 rec, u64 rd, u64 params_ptr){
	u64 rd_pa = virt_to_phys(rd);
	u64 params_pa = virt_to_phys(params_ptr);
	kvm_info("RMI REC CREATE: rec: %lx, rd: %lx, params_ptr: %lx\n", rec, rd, params_ptr);
	kvm_info("RMI REC CREATE: rd_pa: %lx, params_pa: %lx\n", rd_pa, params_pa);
	
	return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_REC_CREATE,
		rec, rd, params_ptr, 0UL, 0UL, 0UL, 0UL}))).ret0;
}

u64 rmi_rec_destroy(u64 rec){
	u64 rec_pa = virt_to_phys(rec);
	kvm_info("RMI REC DESTROY: rec: %lx\n", rec);
	kvm_info("RMI REC DESTROY: rec_pa: %lx\n", rec_pa);
	
	return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_REC_DESTROY,
		rec, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL}))).ret0;
}

u64 rmi_rtt_create(u64 rtt, u64 rd, u64 map_addr, u64 level){
	u64 rd_pa = virt_to_phys(rd);
	u64 map_addr_pa = virt_to_phys(map_addr);
	kvm_info("RMI RTT CREATE: rtt: %lx, rd: %lx, map_addr: %lx, level: %lx\n", rtt, rd, map_addr, level);
	kvm_info("RMI RTT CREATE: rd_pa: %lx, map_addr_pa: %lx\n", rd_pa, map_addr_pa);
	
	return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_RTT_CREATE,
		rtt, rd, map_addr, level, 0UL, 0UL, 0UL}))).ret0;
}

u64 rmi_rtt_destroy(u64 rtt, u64 rd, u64 map_addr, u64 level){
	u64 rd_pa = virt_to_phys(rd);
	u64 map_addr_pa = virt_to_phys(map_addr);
	kvm_info("RMI RTT DESTROY: rtt: %lx, rd: %lx, map_addr: %lx, level: %lx\n", rtt, rd, map_addr, level);
	kvm_info("RMI RTT DESTROY: rd_pa: %lx, map_addr_pa: %lx\n", rd_pa, map_addr_pa);
	
	return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_RTT_DESTROY,
		rtt, rd, map_addr, level, 0UL, 0UL, 0UL}))).ret0;
}

u64 rmi_rec_aux_count(u64 rd, u64 *aux_count){
	u64 rd_pa = virt_to_phys(rd);
	u64 aux_count_pa = virt_to_phys(aux_count);
    kvm_info("RMI REC AUX COUNT: rd: %lx aux_count: %lx\n", rd, aux_count);
	kvm_info("RMI REC AUX COUNT: rd_pa: %lx aux_count_pa: %lx\n", rd_pa, aux_count_pa);
    smc_ret_values rets;

	rets = tftf_smc(&(smc_args) {SMC_RMM_REC_AUX_COUNT, rd, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL});
	*aux_count = rets.ret1;
	return rets.ret0;
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

    // allocate memory for parameters
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
	kvm_info("realm_create() success\n");
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


static inline u_register_t rtt_level_mapsize(u_register_t level)
{
	kvm_info("rtt_level_mapsize: level=%lu\n", level);

	if (level > RTT_MAX_LEVEL) {
		return PAGE_SIZE;
	}

	return (1UL << RTT_LEVEL_SHIFT(level));
}

static inline u_register_t rmi_rtt_init_ripas(u_register_t rd,
	u_register_t map_addr,
	u_register_t level)
{
	kvm_info("rmi_rtt_init_ripas: rd=0x%lx, map_addr=0x%lx, level=%lu\n",
		rd, map_addr, level);

	return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_RTT_INIT_RIPAS,
		rd, map_addr, level, 0UL, 0UL, 0UL, 0UL}))).ret0;
}

static inline u_register_t realm_rtt_create(realm *realm,
	u_register_t addr,
	u_register_t level,
	u_register_t phys)
{
	kvm_info("realm_rtt_create: realm=0x%lx, addr=0x%lx, level=%lu, phys=%lu\n",
		realm, addr, level, phys);

	addr = ALIGN_DOWN(addr, rtt_level_mapsize(level - 1U));
	return rmi_rtt_create(phys, realm->rd, addr, level);
}

static u_register_t rmi_create_rtt_levels(realm *realm,
	u_register_t map_addr,
	u_register_t level,
	u_register_t max_level)
{
	u_register_t rtt, ret;

	while (level++ < max_level) {
		rtt = (u_register_t)kmalloc(R_PAGE_SIZE, GFP_KERNEL);
		if (rtt == NULL) {
			kvm_info("Failed to allocate memory for rtt\n");
			return REALM_ERROR;
		} else {
			ret = rmi_granule_delegate(rtt);
			if (ret != RMI_SUCCESS) {
				kvm_info("Rtt delegation failed,"
					"rtt=0x%lx ret=0x%lx\n", rtt, ret);
				return REALM_ERROR;
			}
		}
		ret = realm_rtt_create(realm, map_addr, level, rtt);
		if (ret != RMI_SUCCESS) {
			kvm_info("Rtt create failed,"
				"rtt=0x%lx ret=0x%lx\n", rtt, ret);
			rmi_granule_undelegate(rtt);
			kfree(rtt);
			return REALM_ERROR;
		}
	}

	kvm_info("realm_init_ipa_state() success\n");

	return REALM_SUCCESS;
}

u64 realm_init_ipa_state(realm *realm_vm, u64 level, u64 start, uint64_t end)
{
	u_register_t rd = realm_vm->rd, ret;
	u_register_t map_size = rtt_level_mapsize(level);

	while (start < end) {
		ret = rmi_rtt_init_ripas(rd, start, level);

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			int cur_level = RMI_RETURN_INDEX(ret);

			if (cur_level < level) {
				ret = rmi_create_rtt_levels(realm_vm,
						start,
						cur_level,
						level);
				if (ret != RMI_SUCCESS) {
					kvm_info("rmi_create_rtt_levels failed,"
						"ret=0x%lx line:%d\n",
						ret, __LINE__);
					return ret;
				}
				/* Retry with the RTT levels in place */
				continue;
			}

			if (level >= RTT_MAX_LEVEL) {
				return REALM_ERROR;
			}

			/* There's an entry at a lower level, recurse */
			realm_init_ipa_state(realm_vm, start, start + map_size,
					     level + 1);
		} else if (ret != RMI_SUCCESS) {
			return REALM_ERROR;
		}

		start += map_size;
	}

	return RMI_SUCCESS;
}