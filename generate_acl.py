#!/usr/bin/env python3

import ipaddress
import re

OLD_ACL_FILE = "old_source_nat.txt"
NAT_FILE = "nat_output.txt"
OUTPUT_FILE = "new_source_nat.txt"


def wildcard_to_network(ip, wildcard):
    wildcard_int = int(ipaddress.IPv4Address(wildcard))
    netmask_int = 0xFFFFFFFF ^ wildcard_int
    netmask = ipaddress.IPv4Address(netmask_int)
    return ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)


def prefix_to_wildcard(prefixlen):
    netmask_int = (0xFFFFFFFF << (32 - prefixlen)) & 0xFFFFFFFF
    wildcard_int = 0xFFFFFFFF ^ netmask_int
    return str(ipaddress.IPv4Address(wildcard_int))


# Parse NAT mappings
nat_mappings = []

with open(NAT_FILE) as f:
    for line in f:
        match = re.match(
            r"ip nat outside source static network "
            r"(\S+) (\S+) /(\d+)",
            line.strip()
        )

        if match:
            original_ip, translated_ip, prefix = match.groups()
            prefix = int(prefix)

            original_network = ipaddress.IPv4Network(
                f"{original_ip}/{prefix}", strict=False
            )

            translated_network = ipaddress.IPv4Network(
                f"{translated_ip}/{prefix}", strict=False
            )

            nat_mappings.append(
                (original_network, translated_network)
            )


# Parse ACLs
acls = {}
current_acl = None
current_remark = None

with open(OLD_ACL_FILE) as f:
    for line in f:
        line = line.strip()

        header = re.match(r"ip access-list extended (\S+)", line)

        if header:
            current_acl = header.group(1)
            current_remark = None
            acls.setdefault(current_acl, [])
            continue

        if current_acl is None:
            continue

        remark = re.match(r"remark (.+)", line)

        if remark:
            current_remark = remark.group(1)
            continue

        permit = re.match(
            r"permit ip (host \S+|\S+ \S+) (\S+) (\S+)",
            line
        )

        if permit and current_remark:
            source, dst_ip, dst_wildcard = permit.groups()

            destination_network = wildcard_to_network(
                dst_ip, dst_wildcard
            )

            acls[current_acl].append(
                (
                    current_remark,
                    source,
                    destination_network
                )
            )


# Generate ACLs
output = []

for acl_name, entries in acls.items():

    output.append(f"ip access-list extended {acl_name}")
    last_remark = None

    for remark, source, acl_network in entries:

        matching_nats = []

        for original_network, translated_network in nat_mappings:
            if original_network.subnet_of(acl_network):
                matching_nats.append(translated_network)

        matching_nats.sort(
            key=lambda n: (int(n.network_address), n.prefixlen)
        )

        if not matching_nats:
            continue

        if remark != last_remark:
            output.append(f" remark {remark}")
            last_remark = remark

        for translated_network in matching_nats:
            wildcard = prefix_to_wildcard(
                translated_network.prefixlen
            )

            output.append(
                f" permit ip {source} "
                f"{translated_network.network_address} {wildcard}"
            )

    output.append("")


# Write output
with open(OUTPUT_FILE, "w") as f:
    f.write("\n".join(output))

print(f"Generated {OUTPUT_FILE}")
