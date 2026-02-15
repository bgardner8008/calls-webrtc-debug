#!/usr/bin/env python3
"""Extract STUN packets around the time of the initial role conflict"""

import json
import sys

def get_role_attr(udp_payload):
    """Extract role attribute from UDP payload hex (0x8029=CONTROLLED, 0x802a=CONTROLLING)"""
    # Parse hex string like "00:01:00:50:21:12:a4:42:..."
    hex_bytes = bytes.fromhex(udp_payload.replace(':', ''))

    # STUN header is 20 bytes: type(2) + length(2) + cookie(4) + txid(12)
    # Attributes start at byte 20
    offset = 20

    while offset < len(hex_bytes):
        # Each attribute: type(2) + length(2) + value(length) + padding
        if offset + 4 > len(hex_bytes):
            break

        attr_type = (hex_bytes[offset] << 8) | hex_bytes[offset + 1]
        attr_len = (hex_bytes[offset + 2] << 8) | hex_bytes[offset + 3]

        if attr_type == 0x8029:  # ICE-CONTROLLED
            # Extract tie-breaker (8 bytes)
            if offset + 4 + 8 <= len(hex_bytes):
                tie_breaker = hex_bytes[offset + 4:offset + 4 + 8].hex(':')
                return f'CONTROLLED (tie: {tie_breaker})'
        elif attr_type == 0x802a:  # ICE-CONTROLLING
            # Extract tie-breaker (8 bytes)
            if offset + 4 + 8 <= len(hex_bytes):
                tie_breaker = hex_bytes[offset + 4:offset + 4 + 8].hex(':')
                return f'CONTROLLING (tie: {tie_breaker})'

        # Move to next attribute (4-byte aligned)
        attr_len_padded = (attr_len + 3) & ~3
        offset += 4 + attr_len_padded

    return 'NO_ROLE'

def main():
    json_file = sys.argv[1] if len(sys.argv) > 1 else 'call3_stun.json'

    with open(json_file, 'r') as f:
        packets = json.load(f)

    # Find packets between server (127.0.0.1:8443) and client (192.168.64.1:61775)
    # Look at ALL packets to find the role conflict

    print(f"Total packets in JSON: {len(packets)}\n")
    print("All server-client packets (looking for role conflict):\n")

    for pkt in packets:
        layers = pkt['_source']['layers']
        frame = layers['frame']
        ip = layers['ip']
        udp = layers['udp']
        stun = layers['stun']

        frame_num = frame['frame.number']
        time_rel = float(frame['frame.time_relative'])
        src_ip = ip['ip.src']
        dst_ip = ip['ip.dst']
        src_port = udp['udp.srcport']
        dst_port = udp['udp.dstport']
        txid = stun['stun.id']

        # Filter for server-client communication around the conflict time
        if time_rel < 40 or time_rel > 52:
            continue

        if not ((src_ip == '127.0.0.1' and dst_ip == '192.168.64.1') or
                (src_ip == '192.168.64.1' and dst_ip == '127.0.0.1')):
            continue

        # Get role attribute by parsing UDP payload
        udp_payload = udp.get('udp.payload', '')
        role = get_role_attr(udp_payload)

        direction = "Server→Client" if src_ip == '127.0.0.1' else "Client→Server"

        print(f"Frame {frame_num:5s} @ {time_rel:12.6f}s | {direction:15s} | {src_ip}:{src_port} → {dst_ip}:{dst_port}")
        print(f"  TxID: {txid}")
        print(f"  Role: {role}")
        print()

if __name__ == '__main__':
    main()
