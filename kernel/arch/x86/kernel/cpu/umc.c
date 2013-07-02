#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/processor.h>
#include "cpu.h"

/*
 * UMC chips appear to be only either 386 or 486,
 * so no special init takes place.  In RHEL6, however, these processors
 * must be marked as unsupported.
 */
static void __cpuinit early_init_umc(struct cpuinfo_x86 *c)
{
	mark_hardware_unsupported("UMC Processor");
}

static const struct cpu_dev __cpuinitconst umc_cpu_dev = {
	.c_vendor	= "UMC",
	.c_ident	= { "UMC UMC UMC" },
	.c_early_init = early_init_umc,
	.c_models = {
		{ .vendor = X86_VENDOR_UMC, .family = 4, .model_names =
		  {
			  [1] = "U5D",
			  [2] = "U5S",
		  }
		},
	},
	.c_x86_vendor	= X86_VENDOR_UMC,
};

cpu_dev_register(umc_cpu_dev);

