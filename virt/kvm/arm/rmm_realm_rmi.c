#include <linux/kvm_host.h>

#include <asm/kvm_mmu.h>
#include <asm/memory.h>

//----------------------------------------------------------------------------------
// smc_ret_values tftf_smc(const smc_args *args)
// {
// 	return (smc_ret_values) {REALM_SUCCESS, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL};
// }


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
    
	return RMI_SUCCESS;
    // return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_GRANULE_DELEGATE,
	// 		addr_pa, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL}))).ret0;
}

u64 rmi_granule_undelegate(u64 addr){
	u64 addr_pa = virt_to_phys(addr);
    kvm_info("RMI GRANULE UNDELEGATE: addr: %lx\n", addr);
	kvm_info("RMI GRANULE UNDELEGATE: addr_pa: %lx\n", addr_pa);

	return RMI_SUCCESS;
	// return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_GRANULE_UNDELEGATE,
	// 		addr, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL}))).ret0;
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
	
	return RMI_SUCCESS;
	// return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_RTT_CREATE,
	// 	rtt, rd, map_addr, level, 0UL, 0UL, 0UL}))).ret0;
}

u64 rmi_rtt_destroy(u64 rtt, u64 rd, u64 map_addr, u64 level){
	u64 rd_pa = virt_to_phys(rd);
	u64 map_addr_pa = virt_to_phys(map_addr);
	kvm_info("RMI RTT DESTROY: rtt: %lx, rd: %lx, map_addr: %lx, level: %lx\n", rtt, rd, map_addr, level);
	kvm_info("RMI RTT DESTROY: rd_pa: %lx, map_addr_pa: %lx\n", rd_pa, map_addr_pa);
	
	return RMI_SUCCESS;
	// return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_RTT_DESTROY,
	// 	rtt, rd, map_addr, level, 0UL, 0UL, 0UL}))).ret0;
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
static void set_realm_params(u32 sec_vm_id, u64 nr_vcpu){
	// request shared memory
	unsigned int core_id;
	kvm_smc_req_t *smc_req;
	core_id = smp_processor_id();
	smc_req = get_smc_req_region(core_id);

	// initialize information of smc_req
	smc_req->sec_vm_id = sec_vm_id;
	smc_req->req_type = REQ_KVM_TO_S_VISOR_BOOT;
	uint64_t qemu_s1ptp;		
	asm volatile("mrs %0, ttbr0_el1\n\t" : "=r"(qemu_s1ptp));
	smc_req->boot.qemu_s1ptp = qemu_s1ptp;
	smc_req->boot.nr_vcpu = nr_vcpu;
}

static void set_rec_params(u32 sec_vm_id){
	// request shared memory
	unsigned int core_id;
	kvm_smc_req_t *smc_req;
	core_id = smp_processor_id();
	smc_req = get_smc_req_region(core_id);

	// initialize information of smc_req
	smc_req->sec_vm_id = sec_vm_id;
	smc_req->req_type = REQ_KVM_TO_S_VISOR_BOOT;
}

// The following are realm management implementation
static unsigned int vm_count = 2;
u64 realm_create(realm *realm_vm){
    rmi_realm_params *params;
    u64 ret;

	// assign vmid
	realm_vm->vmid = vm_count;
	vm_count++;

	// the number of vcpus
	realm_vm->num_aux = 4;

    // change the state of realm to REALM_STATE_NULL
	realm_vm->state = REALM_STATE_NULL;

    // set the range of reserved memory for realm image
    realm_vm->par_size = REALM_MAX_LOAD_IMG_SIZE;

    // allocate reserved memory for realm image
    realm_vm->par_base = (u64)kmalloc(realm_vm->par_size, GFP_KERNEL);
    if (realm_vm->par_base == NULL){
        kvm_info("[error]page_alloc failed, base=0x%lx, size=0x%lx\n",
			  realm_vm->par_base, realm_vm->par_size);
        return REALM_ERROR;
    }

    // allocate and delegate granule for rd (realm descriptor)
    realm_vm->rd = (u64)kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (realm_vm->rd == NULL) {
		kvm_info("[error]Failed to allocate memory for rd\n");
		goto err_free_par;
	} else {
		ret = rmi_granule_delegate(realm_vm->rd);
		if (ret != RMI_SUCCESS) {
			kvm_info("[error]rd delegation failed, rd=0x%lx, ret=0x%lx\n",
					realm_vm->rd, ret);
			goto err_free_rd;
		}
	}

    // allocate and delegate granule for rtt (realm translation table)
    realm_vm->rtt_addr = (u64)kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (realm_vm->rtt_addr == NULL) {
		kvm_info("[error]Failed to allocate memory for rtt_addr\n");
		goto err_undelegate_rd;
	} else {
		ret = rmi_granule_delegate(realm_vm->rtt_addr);
		if (ret != RMI_SUCCESS) {
			kvm_info("[error]rtt delegation failed, rtt_addr=0x%lx, ret=0x%lx\n",
					realm_vm->rtt_addr, ret);
			goto err_free_rtt;
		}
	}

    // allocate memory for parameters
    params = (rmi_realm_params*)kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (params == NULL) {
		kvm_info("[error]Failed to allocate memory for params\n");
		goto err_undelegate_rtt;
	}

    // fill up parameters
	params->features_0 = realm_vm->rmm_feat_reg0;
	params->rtt_level_start = 0L;
	params->rtt_num_start = 1U;
	params->rtt_base = realm_vm->rtt_addr;
    // TODO: replace it with a variable
	params->vmid = realm_vm->vmid;
	params->hash_algo = RMI_HASH_SHA_256;

    // create realm using RMI, requiring rd and parameters
	set_realm_params(realm_vm->vmid, realm_vm->num_aux);
    ret = rmi_realm_create(realm_vm->rd, (u64)params);
	if (ret != RMI_SUCCESS) {
		kvm_info("[error]Realm create failed, rd=0x%lx, ret=0x%lx\n",
			 realm_vm->rd, ret);
		goto err_free_params;
	}

    // deal with realm aux
    // ret = rmi_rec_aux_count(realm_vm->rd, &realm_vm->num_aux);
	// if (ret != RMI_SUCCESS) {
	// 	kvm_info("[error]rmi_rec_aux_count failed, rd=0x%lx, ret=0x%lx\n",
	// 		 realm_vm->rd, ret);
	// 	rmi_realm_destroy(realm_vm->rd);
	// 	goto err_free_params;
	// }

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
		kvm_info("[error]rtt undelegation failed, rtt_addr=0x%lx, ret=0x%lx\n",
		realm_vm->rtt_addr, ret);
	}

err_free_rtt:
	kfree(realm_vm->rtt_addr);

err_undelegate_rd:
	ret = rmi_granule_undelegate(realm_vm->rd);
	if (ret != RMI_SUCCESS) {
		kvm_info("[error]rd undelegation failed, rd=0x%lx, ret=0x%lx\n", 
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
		rtt = (u_register_t)kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (rtt == NULL) {
			kvm_info("[error]Failed to allocate memory for rtt\n");
			return REALM_ERROR;
		} else {
			ret = rmi_granule_delegate(rtt);
			if (ret != RMI_SUCCESS) {
				kvm_info("[error]Rtt delegation failed,"
					"rtt=0x%lx ret=0x%lx\n", rtt, ret);
				return REALM_ERROR;
			}
		}
		ret = realm_rtt_create(realm, map_addr, level, rtt);
		if (ret != RMI_SUCCESS) {
			kvm_info("[error]Rtt create failed,"
				"rtt=0x%lx ret=0x%lx\n", rtt, ret);
			rmi_granule_undelegate(rtt);
			kfree(rtt);
			return REALM_ERROR;
		}
	}

	return REALM_SUCCESS;
}

static u_register_t rmi_rtt_readentry(u_register_t rd, u_register_t map_addr,
	u_register_t level, rtt_entry *rtt)
{
	smc_ret_values rets;

	rets = tftf_smc(&(smc_args) {SMC_RMM_RTT_READ_ENTRY,
		rd, map_addr, level, 0UL, 0UL, 0UL, 0UL});

	rtt->walk_level = rets.ret1;
	rtt->state = rets.ret2 & 0xFF;
	rtt->out_addr = rets.ret3;
	return rets.ret0;
}

static inline u_register_t rmi_rtt_fold(u_register_t rtt, u_register_t rd,
	u_register_t map_addr, u_register_t level)
{
	return ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_RTT_FOLD,
		rtt, rd, map_addr, level, 0UL, 0UL, 0UL}))).ret0;
}

static u_register_t realm_fold_rtt(u_register_t rd, u_register_t addr,
	u_register_t level)
{
	rtt_entry rtt;
	u_register_t ret;

	ret = rmi_rtt_readentry(rd, addr, level, &rtt);
	if (ret != RMI_SUCCESS) {
		kvm_info("[error]Rtt readentry failed,"
			"level=0x%lx addr=0x%lx ret=0x%lx\n",
			level, addr, ret);
		return REALM_ERROR;
	}

	if (rtt.state != RMI_TABLE) {
		kvm_info("[error]Rtt readentry failed, rtt.state=0x%x\n", rtt.state);
		return REALM_ERROR;
	}

	ret = rmi_rtt_fold(rtt.out_addr, rd, addr, level + 1U);
	if (ret != RMI_SUCCESS) {
		kvm_info("[error]Rtt destroy failed,"
			"rtt.out_addr=0x%llx addr=0x%lx ret=0x%lx\n",
			rtt.out_addr, addr, ret);
		return REALM_ERROR;
	}

	kfree(rtt.out_addr);

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
					kvm_info("[error]rmi_create_rtt_levels failed,"
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

	kvm_info("realm_init_ipa_state() success\n");
	return RMI_SUCCESS;
}

static u_register_t realm_map_protected_data(bool unknown, realm *realm_vm,
					     u_register_t target_pa,
					     u_register_t map_size,
					     u_register_t src_pa)
{
	u_register_t rd = realm_vm->rd;
	u_register_t map_level, level;
	u_register_t ret = 0UL;
	u_register_t size;
	u_register_t phys = target_pa;
	u_register_t map_addr = target_pa;

	if (!IS_ALIGNED(map_addr, map_size)) {
		return REALM_ERROR;
	}

	switch (map_size) {
	case PAGE_SIZE:
		map_level = 3UL;
		break;
	case RTT_L2_BLOCK_SIZE:
		map_level = 2UL;
		break;
	default:
		kvm_info("[error]Unknown map_size=0x%lx\n", map_size);
		return REALM_ERROR;
	}

	ret = rmi_rtt_init_ripas(rd, map_addr, map_level);
	if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		ret = rmi_create_rtt_levels(realm_vm, map_addr,
					    RMI_RETURN_INDEX(ret), map_level);
		if (ret != RMI_SUCCESS) {
			kvm_info("[error]rmi_create_rtt_levels failed,"
			      "ret=0x%lx line:%d\n",
			      ret, __LINE__);
			goto err;
		}
		ret = rmi_rtt_init_ripas(rd, map_addr, map_level);
		if (ret != RMI_SUCCESS) {
			kvm_info("[error]rmi_create_rtt_levels failed,"
			      "ret=0x%lx line:%d\n",
			      ret, __LINE__);
			goto err;
		}
	}
	for (size = 0UL; size < map_size; size += PAGE_SIZE) {
		ret = rmi_granule_delegate(phys);
		if (ret != RMI_SUCCESS) {
			kvm_info("[error]Granule delegation failed, PA=0x%lx ret=0x%lx\n",
			      phys, ret);
			return REALM_ERROR;
		}

		ret = rmi_data_create(unknown, phys, rd, map_addr, src_pa);

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			/* Create missing RTTs and retry */
			level = RMI_RETURN_INDEX(ret);
			ret = rmi_create_rtt_levels(realm_vm, map_addr, level,
						    map_level);
			if (ret != RMI_SUCCESS) {
				kvm_info("[error]rmi_create_rtt_levels failed,"
				      "ret=0x%lx line:%d\n",
				      ret, __LINE__);
				goto err;
			}

			ret = rmi_data_create(unknown, phys, rd, map_addr,
					      src_pa);
		}

		if (ret != RMI_SUCCESS) {
			kvm_info("[error]rmi_data_create failed, ret=0x%lx\n", ret);
			goto err;
		}

		phys += PAGE_SIZE;
		src_pa += PAGE_SIZE;
		map_addr += PAGE_SIZE;
	}

	if (map_size == RTT_L2_BLOCK_SIZE) {
		ret = realm_fold_rtt(rd, target_pa, map_level);
		if (ret != RMI_SUCCESS) {
			kvm_info("[error]fold_rtt failed, ret=0x%lx\n", ret);
			goto err;
		}
	}

	if (ret != RMI_SUCCESS) {
		kvm_info("[error]rmi_rtt_mapprotected failed, ret=0x%lx\n", ret);
		goto err;
	}

	return REALM_SUCCESS;

err:
	while (size >= PAGE_SIZE) {
		ret = rmi_data_destroy(rd, map_addr);
		if (ret != RMI_SUCCESS) {
			kvm_info("[error]rmi_rtt_mapprotected failed, ret=0x%lx\n", ret);
		}

		ret = rmi_granule_undelegate(phys);
		if (ret != RMI_SUCCESS) {
			/* Page can't be returned to NS world so is lost */
			kvm_info("[error][error]rmi_granule_undelegate failed\n");
		}
		phys -= PAGE_SIZE;
		size -= PAGE_SIZE;
		map_addr -= PAGE_SIZE;
	}

	return REALM_ERROR;
}

u64 realm_map_payload_image(realm *realm_vm, u64 realm_payload_adr){
	u_register_t src_pa = realm_payload_adr;
	u_register_t i = 0UL;
	u_register_t ret;

	/* MAP image regions */
	while (i < (realm_vm->par_size / PAGE_SIZE)) {
		ret =	realm_map_protected_data(false, realm_vm,
				realm_vm->par_base + i * PAGE_SIZE,
				PAGE_SIZE,
				src_pa + i * PAGE_SIZE);
		if (ret != RMI_SUCCESS) {
			kvm_info("[error][error]realm_map_protected_data failed,"
				"par_base=0x%lx ret=0x%lx\n",
				realm_vm->par_base, ret);
			return REALM_ERROR;
		}
		i++;
	}

	kvm_info("realm_map_payload_image() success\n");
	return REALM_SUCCESS;
}

static void realm_free_rec_aux(u_register_t *aux_pages, unsigned int num_aux)
{
	u_register_t ret;
	unsigned int i;

	for (i = 0U; i < num_aux; i++) {
		ret = rmi_granule_undelegate(aux_pages[i]);
		if (ret != RMI_SUCCESS) {
			kvm_info("[warn] realm_free_rec_aux undelegation failed,"
				"index=%u, ret=0x%lx\n",
				i, ret);
		}
		kfree(aux_pages[i]);
	}
}

static u_register_t realm_alloc_rec_aux(realm *realm_vm,
		rmi_rec_params *params)
{
	u_register_t ret;
	unsigned int i;

	for (i = 0; i < realm_vm->num_aux; i++) {
		params->aux[i] = (u_register_t)kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (params->aux[i] == NULL) {
			kvm_info("[error] Failed to allocate memory for aux rec\n");
			goto err_free_mem;
		}
		ret = rmi_granule_delegate(params->aux[i]);
		if (ret != RMI_SUCCESS) {
			kvm_info("[error] aux rec delegation failed at index=%d, ret=0x%lx\n",
					i, ret);
			goto err_free_mem;
		}

		/* We need a copy in Realm object for final destruction */
		realm_vm->aux_pages[i] = params->aux[i];
	}
	return RMI_SUCCESS;
err_free_mem:
	realm_free_rec_aux(params->aux, i);
	return ret;
}

u64 realm_rec_create(realm *realm_vm){
	rmi_rec_params *rec_params = NULL;
	u_register_t ret;
	unsigned int i;

	/* Allocate memory for run object */
	realm_vm->run = (u_register_t)kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (realm_vm->run == NULL) {
		kvm_info("[error] Failed to allocate memory for run\n");
		return REALM_ERROR;
	}
	(void)memset((void *)realm_vm->run, 0x0, PAGE_SIZE);

	/* Allocate and delegate REC */
	realm_vm->rec = (u_register_t)kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (realm_vm->rec == NULL) {
		kvm_info("[error] Failed to allocate memory for REC\n");
		goto err_free_mem;
	} else {
		ret = rmi_granule_delegate(realm_vm->rec);
		if (ret != RMI_SUCCESS) {
			kvm_info(
				"[error] rec delegation failed, rec=0x%lx, ret=0x%lx\n",
				realm_vm->rd, ret);
			goto err_free_mem;
		}
	}

	/* Allocate memory for rec_params */
	rec_params = (rmi_rec_params *)kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (rec_params == NULL) {
		kvm_info("[error]Failed to allocate memory for rec_params\n");
		goto err_undelegate_rec;
	}
	(void)memset(rec_params, 0x0, PAGE_SIZE);

	/* Populate rec_params */

	for (i = 0UL;
	     i < (sizeof(rec_params->gprs) / sizeof(rec_params->gprs[0]));
	     i++) {
		rec_params->gprs[i] = 0x0UL;
	}

	/* Delegate the required number of auxiliary Granules  */
	ret = realm_alloc_rec_aux(realm_vm, rec_params);
	if (ret != RMI_SUCCESS) {
		kvm_info("[error] REC realm_alloc_rec_aux, ret=0x%lx\n", ret);
		goto err_free_mem;
	}

	rec_params->pc = realm_vm->par_base;
	rec_params->flags = RMI_RUNNABLE;
	rec_params->mpidr = 0x0UL;
	rec_params->num_aux = realm_vm->num_aux;

	/* Create REC  */
	set_rec_params(realm_vm->vmid);
	ret = rmi_rec_create(realm_vm->rec, realm_vm->rd,
			     (u_register_t)rec_params);
	if (ret != RMI_SUCCESS) {
		kvm_info("[error] REC create failed, ret=0x%lx\n", ret);
		goto err_free_rec_aux;
	}

	/* Free rec_params */
	kvm_info("REC create success\n");
	kfree((u_register_t)rec_params);

	return REALM_SUCCESS;

unsigned int index;

err_free_rec_aux:
	realm_free_rec_aux(rec_params->aux, realm_vm->num_aux);

err_undelegate_rec:
	
		ret = rmi_granule_undelegate(realm_vm->rec);
		if (ret != RMI_SUCCESS) {
			kvm_info(
				"[warn] rec undelegation failed, rec=0x%lx, ret=0x%lx\n",
				realm_vm->rec, ret);
		}
	

err_free_mem:
	kfree(realm_vm->run);
	kfree(realm_vm->rec);
	
	kfree((u_register_t)rec_params);

	return REALM_ERROR;
}

u_register_t realm_activate(realm *realm_vm)
{
	u_register_t ret;

	/* Activate Realm  */
	ret = rmi_realm_activate(realm_vm->rd);
	if (ret != RMI_SUCCESS) {
		kvm_info("[error] Realm activate failed, ret=0x%lx\n", ret);
		return REALM_ERROR;
	}

	realm_vm->state = REALM_STATE_ACTIVE;

	kvm_info("Realm activate success\n");
	return REALM_SUCCESS;
}

// TODO: test result may be the tftf self use it to show whether the test is successful
u64 realm_rec_enter(realm *realm, u64 *exit_reason, unsigned int *test_result)
{
	rmi_rec_run *run = (rmi_rec_run *)realm->run;
	u_register_t ret;
	bool re_enter_rec;

	// do {
	// 	re_enter_rec = false;
	// 	// Enter REC
	// 	ret = ((smc_ret_values)(tftf_smc(&(smc_args) {SMC_RMM_REC_ENTER,
	// 			realm->rec, realm->run,
	// 			0UL, 0UL, 0UL, 0UL, 0UL}))).ret0;
	// 	kvm_info("rmi_rec_enter, \
	// 			run->exit_reason=0x%lx, \
	// 			run->exit.esr=0x%llx, \
	// 			EC_BITS=%d, \
	// 			ISS_DFSC_MASK=0x%llx\n",
	// 			run->exit_reason,
	// 			run->exit.esr,
	// 			((EC_BITS(run->exit.esr) == EC_DABORT_CUR_EL)),
	// 			(ISS_BITS(run->exit.esr) & ISS_DFSC_MASK));

	// 	// TODO: deal with exit reason

	// } while (re_enter_rec);

	*exit_reason = run->exit.exit_reason;
	return ret;
}

u_register_t realm_destroy(realm *realm_vm)
{
	u_register_t ret;

	// if (realm->state == REALM_STATE_NULL) {
	// 	return REALM_SUCCESS;
	// }

	// if (realm->state == REALM_STATE_NEW) {
	// 	goto undo_from_new_state;
	// }

	// if (realm->state != REALM_STATE_ACTIVE) {
	// 	kvm_info("[error] Invalid realm state found =0x%x\n", realm->state);
	// 	return REALM_ERROR;
	// }

	/* For each REC - Destroy, undelegate and free */

	set_rec_params(realm_vm->vmid);
	ret = rmi_rec_destroy(realm_vm->rec);
	if (ret != RMI_SUCCESS) {
		kvm_info("[error] REC destroy failed, rec=0x%lx, ret=0x%lx\n",
			 realm_vm->rec, ret);
		return REALM_ERROR;
	}

	ret = rmi_granule_undelegate(realm_vm->rec);
	if (ret != RMI_SUCCESS) {
		kvm_info(
			"[error] rec undelegation failed, rec=0x%lx, ret=0x%lx\n",
			realm_vm->rec, ret);
		return REALM_ERROR;
	}

	realm_free_rec_aux(realm_vm->aux_pages, realm_vm->num_aux);
	kfree(realm_vm->rec);

	/* Free run object */
	kfree(realm_vm->run);

	/*
	 * For each data granule - Destroy, undelegate and free
	 * RTTs (level 1U and below) must be destroyed leaf-upwards,
	 * using RMI_DATA_DESTROY, RMI_RTT_DESTROY and RMI_GRANULE_UNDELEGATE
	 * commands.
	 */
	// if (realm_tear_down_rtt_range(realm, 0UL, 0UL,
	// 		(1UL << (EXTRACT(RMM_FEATURE_REGISTER_0_S2SZ,
	// 		realm->rmm_feat_reg0) - 1))) != RMI_SUCCESS) {
	// 	kvm_info("[error] realm_tear_down_rtt_range\n");
	// 	return REALM_ERROR;
	// }
	// if (realm_tear_down_rtt_range(realm, 0UL, realm->ipa_ns_buffer,
	// 		(realm->ipa_ns_buffer + realm->ns_buffer_size)) !=
	// 		RMI_SUCCESS) {
	// 	kvm_info("[error] realm_tear_down_rtt_range\n");
	// 	return REALM_ERROR;
	// }
undo_from_new_state:

	/*
	 * RD Destroy, undelegate and free
	 * RTT(L0) undelegate and free
	 * PAR free
	 */
	set_realm_params(realm_vm->vmid, realm_vm->num_aux);
	ret = rmi_realm_destroy(realm_vm->rd);
	if (ret != RMI_SUCCESS) {
		kvm_info("[error] Realm destroy failed, rd=0x%lx, ret=0x%lx\n",
				realm_vm->rd, ret);
		return REALM_ERROR;
	}

	ret = rmi_granule_undelegate(realm_vm->rd);
	if (ret != RMI_SUCCESS) {
		kvm_info("[error] rd undelegation failed, rd=0x%lx, ret=0x%lx\n",
				realm_vm->rd, ret);
		return REALM_ERROR;
	}

	ret = rmi_granule_undelegate(realm_vm->rtt_addr);
	if (ret != RMI_SUCCESS) {
		kvm_info("[error] rtt undelegation failed, rtt_addr=0x%lx, ret=0x%lx\n",
				realm_vm->rtt_addr, ret);
		return REALM_ERROR;
	}

	kfree(realm_vm->rd);
	kfree(realm_vm->rtt_addr);
	kfree(realm_vm->par_base);

	return REALM_SUCCESS;
}