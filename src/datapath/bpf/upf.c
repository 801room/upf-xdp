#include "upf.h"
#include "logger.h"
#include "maps.h"

static u32 pfcp_pdr_match_attribute(pfcp_pdr_t *p_pdr,u32 ueIp)
{
  // clang-format off
  if( p_pdr->ueIp != ueIp){
        bpf_debug("Not match:\n");
        return 1;
    }
  // clang-format on
  // All the attributes were matched.
  bpf_debug("All atrributes were matched!!\n");
  return 0;
}
static u32 gtpu_decap(struct xdp_md *ctx, struct gtpuhdr *gtpuh)
{
    int delta;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    void *eth_cpy = (void *)(long)ctx->data+36;
    if(data+50>data_end){
        bpf_debug("gtpu_decap:Invalid packet\n");
        return XDP_ABORTED;
    }
    bpf_debug("gtpu_decap:memcpy\n");
    delta = 36;
    __builtin_memcpy(eth_cpy, data, sizeof(struct ethhdr));
    if(0==bpf_xdp_adjust_head(ctx, delta)){
        return XDP_PASS;
    }else{
        return XDP_DROP;
    }
}

static u32 pdr_lookup_uplink(struct xdp_md *ctx, struct gtpuhdr *gtpuh)
{
    pfcp_pdr_t *p_pdr;
    u32 ueIp;
    struct iphdr *p_iph;
    void *data_end = (void *)(long)ctx->data_end;
    if((u8 *)gtpuh + GTPV1U_MSG_HEADER_MIN_SIZE > data_end) {
        bpf_debug("Invalid UDP packet\n");
        return XDP_ABORTED;
    }

    u8 *p_data = (u8 *)gtpuh + GTPV1U_MSG_HEADER_MIN_SIZE;
    if(p_data+sizeof(struct iphdr)>data_end){
        return XDP_ABORTED;
    }
    p_iph = (struct iphdr *)p_data;
    teid_t teid = htonl(gtpuh->teid);
    bpf_debug("GTP GPDU teid %d with IPv4 payload received\n", teid);

    p_pdr = bpf_map_lookup_elem(&m_teid_pdrs, &teid);
    if(!p_pdr) {
        bpf_debug("Error - no find pdr.");
        return XDP_DROP;
    }
    ueIp = p_iph->saddr;
    if(pfcp_pdr_match_attribute(p_pdr, ueIp) == 0){
        return gtpu_decap(ctx,gtpuh);
    }
    return XDP_DROP;
}

static u32 pdr_lookup_downlink(struct xdp_md *ctx, struct iphdr *iph)
{
    return XDP_PASS;
}

static u32 gtp_handle(struct xdp_md *ctx, struct gtpuhdr *gtpuh)
{
  void *data_end = (void *)(long)ctx->data_end;
  if((void *)gtpuh + sizeof(*gtpuh) > data_end) {
    bpf_debug("Invalid GTPU packet\n");
    return XDP_ABORTED;
  }

  if(gtpuh->message_type != GTPU_G_PDU) {
    bpf_debug("Message type 0x%x is not GTPU GPDU(0x%x)\n", gtpuh->message_type, GTPU_G_PDU);
  }else{
    bpf_debug("GTP GPDU received\n");
  }
  return pdr_lookup_uplink(ctx, gtpuh);
}


static u32 udp_handle(struct xdp_md *ctx, struct udphdr *udph)
{
  void *data_end = (void *)(long)ctx->data_end;
  u32 dport;

  /* Hint: +1 is sizeof(struct udphdr) */
  if((void *)udph + sizeof(*udph) > data_end) {
    bpf_debug("Invalid UDP packet\n");
    return XDP_ABORTED;
  }

  bpf_debug("UDP packet validated\n");
  dport = htons(udph->dest);

  switch(dport) {
  case GTP_UDP_PORT:
    return gtp_handle(ctx, (struct gtpuhdr *)(udph + 1));
  default:
    bpf_debug("GTP port %lu not valid\n", dport);
    return XDP_PASS;
  }
}

static u32 match_ueip(u32 ip)
{
    return 0;
}

static u32 ipv4_handle(struct xdp_md *ctx, struct iphdr *iph)
{
  void *data_end = (void *)(long)ctx->data_end;
  // Type need to match map.
  u32 ip_dest;
  // Hint: +1 is sizeof(struct iphdr)
  if((void *)iph + sizeof(*iph) > data_end) {
    bpf_debug("Invalid IPv4 packet\n");
    return XDP_ABORTED;
  }
   ip_dest = iph->daddr;
   bpf_debug("Valid IPv4 packet: raw daddr:0x%x\n", ip_dest);

  if(match_ueip(ip_dest)){
      //downlink
      return pdr_lookup_downlink(ctx,iph);
  }else{
      //uplink
      switch(iph->protocol) {
          case IPPROTO_UDP:
            return udp_handle(ctx, (struct udphdr *)(iph + 1));
          default:
            return XDP_PASS;
      }
  }
  return XDP_PASS;
}

static u32 eth_handle(struct xdp_md *ctx, struct ethhdr *ethh)
{
  void *data_end = (void *)(long)ctx->data_end;
  u16 eth_type;
  u64 offset;
  struct vlan_hdr *vlan_hdr;

  offset = sizeof(*ethh);
  if((void *)ethh + offset > data_end) {
    bpf_debug("Cannot parse L2\n");
    return XDP_PASS;
  }

  eth_type = htons(ethh->h_proto);
  switch(eth_type) {
      case ETH_P_IP:
        return ipv4_handle(ctx, (struct iphdr *)((void *)ethh + offset));
      case ETH_P_IPV6:
      // Skip non 802.3 Ethertypes
      case ETH_P_ARP:
      // Skip non 802.3 Ethertypes
      // Fall-through
      default:
        bpf_debug("Cannot parse L2: L3off:%llu proto:0x%x\n", offset, eth_type);
        return XDP_PASS;
  }
  return XDP_PASS;
}

SEC("xdp")
int upf_input(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  return eth_handle(ctx, eth);
}

char _license[] SEC("license") = "GPL";