#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>


	.text

ENTRY(asm_tftf_smc64)
	/*x8 might be clobbered across the SMC call so save it on the stack.*/
	str	x8, [sp, #-16]!

	smc #0x18

	/* Pop x8 into a caller-saved register */
	ldr	x9, [sp], #16

	/*
	 * Return values are stored in x0-x7, put them in the 'smc_ret_values'
	 * return structure
	 */
	stp	x0, x1, [x9, #0]
	stp	x2, x3, [x9, #16]
	stp	x4, x5, [x9, #32]
	stp	x6, x7, [x9, #48]

	ret
ENDPROC(asm_tftf_smc64)