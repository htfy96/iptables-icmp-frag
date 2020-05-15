#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <xtables.h>

#include "../../../kernel-module/ipt_icmp_frag.h"

struct xt_icmp_frag_target_info {
    uint16_t mtu;
};

static void icmp_frag_help(void) {
    printf("icmp_frag options:\n"
                " --mtu mtu     Set icmp frag mtu\n");
}

enum {
    O_MTU = 0,
    F_OP_ANY = 1 << 15
};

#define s struct xt_icmp_frag_tginfo
static const struct xt_option_entry icmp_tg_opts[] = {
	{.name = "mtu", .id = O_MTU, .type = XTTYPE_UINT16,
	 .excl = F_OP_ANY},
	XTOPT_TABLEEND,
};
#undef s

static void icmp_frag_init(struct xt_entry_target* target) {}

static void icmp_frag_parse(struct xt_option_call* cb) {
    struct xt_icmp_frag_target_info* info = cb->data;
	xtables_option_parse(cb);
    switch (cb->entry->id) {
        case O_MTU:
            info->mtu = cb->val.u16;
            break;
    }
}

static void icmp_frag_check(struct xt_fcheck_call *cb) {}
static void icmp_frag_print(const void *ip,
                           const struct xt_entry_target *target, int numeric) {
	const struct xt_icmp_frag_target_info *fraginfo =
		(const struct xt_icmp_frag_target_info *)target->data;
    printf(" icmp_frag MTU %u", fraginfo->mtu);
}

static void
icmp_frag_save(const void* ip, const struct xt_entry_target* target) {
    const struct xt_icmp_frag_target_info *info = (const void*)target->data;
    printf(" --mtu %u", info->mtu);
}

static struct xtables_target icmp_frag_reg[] = {
    {
		.version       = XTABLES_VERSION,
		.name          = "icmp_frag",
		.revision      = 0,
		.family        = NFPROTO_UNSPEC,
		.size          = XT_ALIGN(sizeof(struct xt_icmp_frag_target_info)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_icmp_frag_target_info)),
		.help          = icmp_frag_help,
		.init          = icmp_frag_init,
		.print         = icmp_frag_print,
		.save          = icmp_frag_save,
		.x6_parse      = icmp_frag_parse,
		.x6_fcheck     = icmp_frag_check,
		.x6_options    = icmp_tg_opts,
    }
};
void _init(void)
{
	xtables_register_targets(icmp_frag_reg, 1);
}
