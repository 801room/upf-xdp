#ifndef __BPF_UPF_H
#define __BPF_UPF_H
#include "types.h"
#include <stdint.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#define OUTER_HEADER_REMOVAL_GTPU_UDP_IPV4 0
#define OUTER_HEADER_REMOVAL_GTPU_UDP_IPV6 1
#define OUTER_HEADER_REMOVAL_UDP_IPV4 2
#define OUTER_HEADER_REMOVAL_UDP_IPV6 3
#define GTPV1U_MSG_HEADER_MIN_SIZE        8
#define GTPU_G_PDU (255)
#define GTP_UDP_PORT 2152u

enum destination_interface_value_e
{
  /* Request / Initial message */
  INTERFACE_VALUE_ACCESS = 0,
  INTERFACE_VALUE_CORE = 1,
  INTERFACE_VALUE_SGI_LAN_N6_LAN = 2,
  INTERFACE_VALUE_CP_FUNCTION = 3,
  INTERFACE_VALUE_LI_FUNCTION = 4
};


struct gtpuhdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned int pn : 1;
  unsigned int s : 1;
  unsigned int e : 1;
  unsigned int spare : 1;
  unsigned int pt : 1;
  unsigned int version : 3;
#elif __BYTE_ORDER == __BIG_ENDIAN
  unsigned int version : 3;
  unsigned int pt : 1;
  unsigned int spare : 1;
  unsigned int e : 1;
  unsigned int s : 1;
  unsigned int pn : 1;
#else
#error "Please fix <bits/endian.h>"
#endif
  // Message Type: This field indicates the type of GTP-U message.
  uint8_t message_type;
  // Length: This field indicates the length in octets of the payload, i.e. the rest of the packet following the mandatory
  // part of the GTP header (that is the first 8 octets). The Sequence Number, the N-PDU Number or any Extension
  // headers shall be considered to be part of the payload, i.e. included in the length count.
  uint16_t message_length;
  // Tunnel Endpoint Identifier (TEID): This field unambiguously identifies a tunnel endpoint in the receiving
  // GTP-U protocol entity. The receiving end side of a GTP tunnel locally assigns the TEID value the transmitting
  // side has to use. The TEID value shall be assigned in a non-predictable manner for PGW S5/S8/S2a/S2b
  // interfaces (see 3GPP TS 33.250 [32]). The TEID shall be used by the receiving entity to find the PDP context,
  // except for the following cases:
  // -) The Echo Request/Response and Supported Extension Headers notification messages, where the Tunnel
  //    Endpoint Identifier shall be set to all zeroes
  // -) The Error Indication message where the Tunnel Endpoint Identifier shall be set to all zeros.
  uint32_t teid;

  /*The options start here. */
};

#ifndef BPF_UTILS_H
#define BPF_UTILS_H

#ifndef htons
#define htons(x) __constant_htons((x))
#endif

#ifndef htonl
#define htonl(x) __constant_htonl((x))
#endif

#endif

typedef u32 teid_t;
typedef struct outer_header_removal_s
{
  u8 outer_header_removal_description;
} outer_header_removal_t;

typedef struct ue_ip_address
{
  u8 ipv6d : 1; // This bit is only applicable to the UE IP address IE in the PDI IE and whhen V6 bit is set to "1". If this bit is set to "1", then the IPv6 Prefix Delegation Bits field shall be present, otherwise the UP function shall consider IPv6 prefix is default /64.
  u8 sd : 1;    // This bit is only applicable to the UE IP Address IE in the PDI IE. It shall be set to "0" and ignored by the receiver in IEs other than PDI IE. In the PDI IE, if this bit is set to "0", this indicates a Source IP address; if this bit is set to "1", this indicates a Destination IP address.
  u8 v4 : 1;    // If this bit is set to "1", then the IPv4 address field shall be present in the UE IP Address, otherwise the IPv4 address field shall not be present.
  u8 v6 : 1;    // If this bit is set to "1", then the IPv6 address field shall be present in the UE IP Address, otherwise the IPv6 address field shall not be present.
  u32 ipv4_address;
  u8 ipv6_address[16];
  u8 ipv6_prefix_delegation_bits;
}ue_ip_address_t;

typedef struct source_interface
{
  u8 interface_value;
} source_interface_t;

typedef struct fteid
{
  u8 chid : 1;
  u8 ch : 1;
  u8 v4 : 1;
  u8 v6 : 1;
  teid_t teid;
  u32 ipv4_address;
  u8 ipv6_address[16];
  u8 choose_id;
}fteid_t;

typedef struct pdi
{
  fteid_t fteit;
  source_interface_t source_interface;
  ue_ip_address_t ue_ip_address;
}pdi_t;

typedef struct pfcp_pdr_s
{
  u32 ueIp;
} pfcp_pdr_t;

#endif
