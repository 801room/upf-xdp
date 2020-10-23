#ifndef __MAPS_H__
#define __MAPS_H__
#include "bpf_helpers.h"
#include "upf.h"

BPF_MAP_DEF(m_teid_pdrs) = {
	.map_type    = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(teid_t), // teid
	.value_size  = sizeof(__u32), // list of pdr
	.max_entries = 10,
};
BPF_MAP_ADD(m_teid_pdrs);
#endif // __MAPS_H__