#include <asm/smc_helper.h>
#include <asm/kvm_hyp.h>

smc_ret_values asm_tftf_smc64(uint32_t fid,
			      u_register_t arg1,
			      u_register_t arg2,
			      u_register_t arg3,
			      u_register_t arg4,
			      u_register_t arg5,
			      u_register_t arg6,
			      u_register_t arg7);

smc_ret_values tftf_smc(const smc_args *args)
{
	uint32_t arg1 = 1999;
	return asm_tftf_smc64(args->fid,
			      arg1,
			      args->arg2,
			      args->arg3,
			      args->arg4,
			      args->arg5,
			      args->arg6,
			      args->arg7);
}
