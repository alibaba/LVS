/* Auto-generated from route_types.txt by gawk. */
/* Do not edit! */

#ifndef _QUAGGA_ROUTE_TYPES_H
#define _QUAGGA_ROUTE_TYPES_H

/* zebra */
#define QUAGGA_REDIST_STR_ZEBRA \
"(rip|ripng|ospf|ospf6|isis|bgp)"
#define QUAGGA_REDIST_HELP_STR_ZEBRA \
  "Routing Information Protocol (RIP)\n" \
  "Routing Information Protocol next-generation (IPv6) (RIPng)\n" \
  "Open Shortest Path First (OSPFv2)\n" \
  "Open Shortest Path First (IPv6) (OSPFv3)\n" \
  "Intermediate System to Intermediate System (IS-IS)\n" \
  "Border Gateway Protocol (BGP)\n"

/* ripd */
#define QUAGGA_REDIST_STR_RIPD \
"(kernel|connected|static|ospf|isis|bgp)"
#define QUAGGA_REDIST_HELP_STR_RIPD \
  "Kernel routes (not installed via the zebra RIB)\n" \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Open Shortest Path First (OSPFv2)\n" \
  "Intermediate System to Intermediate System (IS-IS)\n" \
  "Border Gateway Protocol (BGP)\n"

/* ripngd */
#define QUAGGA_REDIST_STR_RIPNGD \
"(kernel|connected|static|ospf6|isis|bgp)"
#define QUAGGA_REDIST_HELP_STR_RIPNGD \
  "Kernel routes (not installed via the zebra RIB)\n" \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Open Shortest Path First (IPv6) (OSPFv3)\n" \
  "Intermediate System to Intermediate System (IS-IS)\n" \
  "Border Gateway Protocol (BGP)\n"

/* ospfd */
#define QUAGGA_REDIST_STR_OSPFD \
"(kernel|connected|static|rip|isis|bgp)"
#define QUAGGA_REDIST_HELP_STR_OSPFD \
  "Kernel routes (not installed via the zebra RIB)\n" \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Routing Information Protocol (RIP)\n" \
  "Intermediate System to Intermediate System (IS-IS)\n" \
  "Border Gateway Protocol (BGP)\n"

/* ospf6d */
#define QUAGGA_REDIST_STR_OSPF6D \
"(kernel|connected|static|ripng|isis|bgp)"
#define QUAGGA_REDIST_HELP_STR_OSPF6D \
  "Kernel routes (not installed via the zebra RIB)\n" \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Routing Information Protocol next-generation (IPv6) (RIPng)\n" \
  "Intermediate System to Intermediate System (IS-IS)\n" \
  "Border Gateway Protocol (BGP)\n"

/* isisd */
#define QUAGGA_REDIST_STR_ISISD \
"(kernel|connected|static|rip|ripng|ospf|ospf6|bgp)"
#define QUAGGA_REDIST_HELP_STR_ISISD \
  "Kernel routes (not installed via the zebra RIB)\n" \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Routing Information Protocol (RIP)\n" \
  "Routing Information Protocol next-generation (IPv6) (RIPng)\n" \
  "Open Shortest Path First (OSPFv2)\n" \
  "Open Shortest Path First (IPv6) (OSPFv3)\n" \
  "Border Gateway Protocol (BGP)\n"

/* bgpd */
#define QUAGGA_REDIST_STR_BGPD \
"(kernel|connected|static|rip|ripng|ospf|ospf6|isis)"
#define QUAGGA_REDIST_HELP_STR_BGPD \
  "Kernel routes (not installed via the zebra RIB)\n" \
  "Connected routes (directly attached subnet or host)\n" \
  "Statically configured routes\n" \
  "Routing Information Protocol (RIP)\n" \
  "Routing Information Protocol next-generation (IPv6) (RIPng)\n" \
  "Open Shortest Path First (OSPFv2)\n" \
  "Open Shortest Path First (IPv6) (OSPFv3)\n" \
  "Intermediate System to Intermediate System (IS-IS)\n"

#endif /* _QUAGGA_ROUTE_TYPES_H */
