#!/usr/bin/env python3
"""
RFC 8445 Section 7.3.1.1 Validator

Analyzes STUN packets in pcap files to validate ICE role conflict resolution
according to RFC 8445. Extracts tie-breaker values from UDP payloads and
verifies correct role negotiation behavior.

Usage:
    # Analyze pcap file directly (will export to JSON first)
    ./validate_rfc8445.py capture.pcap --server-ip 1.2.3.4 --server-port 8443

    # Analyze pre-exported JSON
    ./validate_rfc8445.py stun.json --format json --server-ip 1.2.3.4
"""

import argparse
import json
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple


# STUN message types
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS_RESPONSE = 0x0101
STUN_BINDING_ERROR_RESPONSE = 0x0111

# STUN attribute types
ATTR_ICE_CONTROLLED = 0x8029
ATTR_ICE_CONTROLLING = 0x802a
ATTR_ERROR_CODE = 0x0009


@dataclass
class STUNMessage:
    """Parsed STUN message with role and tie-breaker information"""
    timestamp: float
    frame_num: str
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    msg_type: int
    transaction_id: str
    role: Optional[str]  # 'CONTROLLING' or 'CONTROLLED'
    tie_breaker: Optional[int]  # uint64
    error_code: Optional[int]  # For error responses

    def is_binding_request(self) -> bool:
        return self.msg_type == STUN_BINDING_REQUEST

    def is_error_response(self) -> bool:
        return self.msg_type == STUN_BINDING_ERROR_RESPONSE

    def direction(self, server_ip: str) -> str:
        """Return 'Client→Server' or 'Server→Client'"""
        return "Server→Client" if self.src_ip == server_ip else "Client→Server"


def parse_stun_message(udp_payload_hex: str) -> Tuple[int, Optional[str], Optional[int], Optional[int]]:
    """
    Parse STUN message from UDP payload hex string.

    Returns:
        (msg_type, role, tie_breaker, error_code)
        - msg_type: STUN message type (0x0001, 0x0101, 0x0111, etc.)
        - role: 'CONTROLLING' or 'CONTROLLED' or None
        - tie_breaker: uint64 value or None
        - error_code: error code number or None
    """
    try:
        hex_bytes = bytes.fromhex(udp_payload_hex.replace(':', ''))

        if len(hex_bytes) < 20:
            return (0, None, None, None)

        # Parse STUN header
        # Bytes 0-1: Message Type
        # Bytes 2-3: Message Length
        # Bytes 4-7: Magic Cookie (0x2112A442)
        # Bytes 8-19: Transaction ID
        msg_type = struct.unpack('>H', hex_bytes[0:2])[0]

        # Parse attributes starting at byte 20
        offset = 20
        role = None
        tie_breaker = None
        error_code = None

        while offset + 4 <= len(hex_bytes):
            attr_type = struct.unpack('>H', hex_bytes[offset:offset+2])[0]
            attr_len = struct.unpack('>H', hex_bytes[offset+2:offset+4])[0]

            if offset + 4 + attr_len > len(hex_bytes):
                break

            # Extract role and tie-breaker
            if attr_type == ATTR_ICE_CONTROLLED:
                if attr_len >= 8:
                    tie_breaker = struct.unpack('>Q', hex_bytes[offset+4:offset+12])[0]
                    role = 'CONTROLLED'
            elif attr_type == ATTR_ICE_CONTROLLING:
                if attr_len >= 8:
                    tie_breaker = struct.unpack('>Q', hex_bytes[offset+4:offset+12])[0]
                    role = 'CONTROLLING'
            elif attr_type == ATTR_ERROR_CODE:
                if attr_len >= 4:
                    # Error code is in bytes 2-3 of attribute value
                    # Byte 2: class (1-6), Byte 3: number (0-99)
                    error_class = hex_bytes[offset+6] & 0x07
                    error_number = hex_bytes[offset+7]
                    error_code = error_class * 100 + error_number

            # Move to next attribute (4-byte aligned)
            attr_len_padded = (attr_len + 3) & ~3
            offset += 4 + attr_len_padded

        return (msg_type, role, tie_breaker, error_code)

    except Exception as e:
        print(f"Warning: Failed to parse STUN message: {e}", file=sys.stderr)
        return (0, None, None, None)


def export_pcap_to_json(pcap_file: str) -> str:
    """Export pcap to JSON using tshark, returns path to JSON file"""
    print(f"Exporting {pcap_file} to JSON using tshark...")

    # Create temporary file for JSON output
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    json_path = temp_file.name
    temp_file.close()

    # Run tshark to export STUN packets
    cmd = [
        '/usr/local/bin/tshark',
        '-r', pcap_file,
        '-Y', 'stun',
        '-T', 'json'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        with open(json_path, 'w') as f:
            f.write(result.stdout)
        print(f"Exported to {json_path}")
        return json_path
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}", file=sys.stderr)
        print(f"stderr: {e.stderr}", file=sys.stderr)
        sys.exit(1)


def parse_json_packets(json_file: str, server_ip: Optional[str] = None) -> List[STUNMessage]:
    """Parse STUN messages from tshark JSON export"""
    with open(json_file, 'r') as f:
        packets = json.load(f)

    messages = []

    for pkt in packets:
        try:
            layers = pkt['_source']['layers']
            frame = layers['frame']
            ip = layers['ip']
            udp = layers['udp']
            stun = layers.get('stun', {})

            # Extract basic packet info
            # Handle both epoch float and ISO timestamp string
            time_epoch = frame.get('frame.time_epoch', frame.get('frame.time'))
            try:
                timestamp = float(time_epoch)
            except (ValueError, TypeError):
                # Parse ISO timestamp (e.g., "2026-02-15T22:33:57.429541000Z")
                # Remove 'Z' suffix and handle nanosecond precision
                time_str = str(time_epoch).rstrip('Z')
                # Python datetime only handles microseconds, truncate nanoseconds
                if '.' in time_str:
                    base, frac = time_str.split('.')
                    frac = frac[:6]  # Keep only microseconds
                    time_str = f"{base}.{frac}"
                dt = datetime.fromisoformat(time_str)
                timestamp = dt.timestamp()

            frame_num = frame['frame.number']
            src_ip = ip['ip.src']
            dst_ip = ip['ip.dst']
            src_port = udp['udp.srcport']
            dst_port = udp['udp.dstport']
            transaction_id = stun.get('stun.id', 'unknown')

            # Parse UDP payload to get STUN details
            udp_payload = udp.get('udp.payload', '')
            if not udp_payload:
                continue

            msg_type, role, tie_breaker, error_code = parse_stun_message(udp_payload)

            if msg_type == 0:
                continue

            messages.append(STUNMessage(
                timestamp=timestamp,
                frame_num=frame_num,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                msg_type=msg_type,
                transaction_id=transaction_id,
                role=role,
                tie_breaker=tie_breaker,
                error_code=error_code
            ))

        except (KeyError, ValueError) as e:
            print(f"Warning: Failed to parse packet: {e}", file=sys.stderr)
            continue

    return sorted(messages, key=lambda m: m.timestamp)


def validate_rfc8445(messages: List[STUNMessage], server_ip: str) -> Dict:
    """
    Validate RFC 8445 Section 7.3.1.1 compliance.

    Tracks role transitions and validates:
    1. Tie-breaker values never change per endpoint
    2. When conflict detected (both same role), correct side sends 487
    3. When 487 received, receiving side switches roles
    """
    results = {
        'violations': [],
        'conflicts': [],
        'role_switches': [],
        'client_tie_breaker': None,
        'server_tie_breaker': None,
        'client_roles': [],
        'server_roles': []
    }

    # Track current roles
    client_role = None
    server_role = None

    for msg in messages:
        if not msg.is_binding_request():
            continue

        is_from_server = msg.src_ip == server_ip
        direction = msg.direction(server_ip)

        # Track tie-breaker values
        if msg.tie_breaker is not None:
            if is_from_server:
                if results['server_tie_breaker'] is None:
                    results['server_tie_breaker'] = msg.tie_breaker
                elif results['server_tie_breaker'] != msg.tie_breaker:
                    results['violations'].append({
                        'type': 'TIE_BREAKER_CHANGED',
                        'endpoint': 'server',
                        'timestamp': msg.timestamp,
                        'frame': msg.frame_num,
                        'old': results['server_tie_breaker'],
                        'new': msg.tie_breaker,
                        'message': f"Server tie-breaker changed from {results['server_tie_breaker']} to {msg.tie_breaker}"
                    })
            else:
                if results['client_tie_breaker'] is None:
                    results['client_tie_breaker'] = msg.tie_breaker
                elif results['client_tie_breaker'] != msg.tie_breaker:
                    results['violations'].append({
                        'type': 'TIE_BREAKER_CHANGED',
                        'endpoint': 'client',
                        'timestamp': msg.timestamp,
                        'frame': msg.frame_num,
                        'old': results['client_tie_breaker'],
                        'new': msg.tie_breaker,
                        'message': f"Client tie-breaker changed from {results['client_tie_breaker']} to {msg.tie_breaker}"
                    })

        # Track role changes
        if msg.role:
            if is_from_server:
                if server_role and server_role != msg.role:
                    results['role_switches'].append({
                        'endpoint': 'server',
                        'timestamp': msg.timestamp,
                        'frame': msg.frame_num,
                        'old_role': server_role,
                        'new_role': msg.role,
                        'direction': direction
                    })
                server_role = msg.role
                results['server_roles'].append({
                    'timestamp': msg.timestamp,
                    'frame': msg.frame_num,
                    'role': msg.role
                })
            else:
                if client_role and client_role != msg.role:
                    results['role_switches'].append({
                        'endpoint': 'client',
                        'timestamp': msg.timestamp,
                        'frame': msg.frame_num,
                        'old_role': client_role,
                        'new_role': msg.role,
                        'direction': direction
                    })
                client_role = msg.role
                results['client_roles'].append({
                    'timestamp': msg.timestamp,
                    'frame': msg.frame_num,
                    'role': msg.role
                })

            # Detect role conflicts
            if client_role and server_role and client_role == server_role:
                # Determine who should send 487 based on RFC 8445 Section 7.3.1.1
                # The logic differs depending on which role both agents are in:
                should_send_487 = None
                if results['client_tie_breaker'] and results['server_tie_breaker']:
                    if client_role == 'CONTROLLING':
                        # Both CONTROLLING: Agent with higher/equal tie-breaker sends 487
                        if results['client_tie_breaker'] >= results['server_tie_breaker']:
                            should_send_487 = 'client'
                        else:
                            should_send_487 = 'server'
                    else:  # Both CONTROLLED
                        # Both CONTROLLED: Agent with lower tie-breaker sends 487
                        if results['client_tie_breaker'] < results['server_tie_breaker']:
                            should_send_487 = 'client'
                        else:
                            should_send_487 = 'server'

                results['conflicts'].append({
                    'timestamp': msg.timestamp,
                    'frame': msg.frame_num,
                    'role': client_role,
                    'client_tie_breaker': results['client_tie_breaker'],
                    'server_tie_breaker': results['server_tie_breaker'],
                    'direction': direction,
                    'should_send_487': should_send_487
                })

    # Find 487 errors and categorize by direction
    error_487_messages = [m for m in messages if m.is_error_response() and m.error_code == 487]
    results['error_487_count'] = len(error_487_messages)
    results['error_487_messages'] = error_487_messages

    # Count 487s by direction
    server_487_count = sum(1 for m in error_487_messages if m.src_ip == server_ip)
    client_487_count = sum(1 for m in error_487_messages if m.src_ip != server_ip)

    # Count required 487s by side
    server_should_send_487 = sum(1 for c in results['conflicts'] if c['should_send_487'] == 'server')
    client_should_send_487 = sum(1 for c in results['conflicts'] if c['should_send_487'] == 'client')

    # Detect missing 487 responses as RFC violations
    if server_should_send_487 > server_487_count:
        missing = server_should_send_487 - server_487_count
        results['violations'].append({
            'type': 'MISSING_487_RESPONSE',
            'endpoint': 'server',
            'message': f"Server failed to send {missing} required 487 error responses ({server_487_count} sent, {server_should_send_487} required)",
            'required': server_should_send_487,
            'actual': server_487_count,
            'missing': missing
        })

    if client_should_send_487 > client_487_count:
        missing = client_should_send_487 - client_487_count
        results['violations'].append({
            'type': 'MISSING_487_RESPONSE',
            'endpoint': 'client',
            'message': f"Client failed to send {missing} required 487 error responses ({client_487_count} sent, {client_should_send_487} required)",
            'required': client_should_send_487,
            'actual': client_487_count,
            'missing': missing
        })

    # Check for improper role switches after sending 487 errors
    # RFC 8445: Only switch role when RECEIVING 487, not when SENDING it
    for err_msg in error_487_messages:
        err_sender_is_server = err_msg.src_ip == server_ip
        err_timestamp = err_msg.timestamp

        # Look for role switches by the sender within 1 second of sending the 487
        for switch in results['role_switches']:
            switch_is_server = switch['endpoint'] == 'server'

            # Check if the switch is by the same endpoint that sent the 487
            if err_sender_is_server == switch_is_server:
                time_diff = abs(switch['timestamp'] - err_timestamp)

                # If role switch happens within 1 second of sending 487, it's likely a violation
                if time_diff < 1.0:
                    endpoint = 'server' if err_sender_is_server else 'client'
                    results['violations'].append({
                        'type': 'IMPROPER_ROLE_SWITCH_AFTER_SENDING_487',
                        'endpoint': endpoint,
                        'message': f"{endpoint.capitalize()} switched roles {time_diff*1000:.1f}ms after sending 487 error (frame {err_msg.frame_num}). Per RFC 8445, agent should only switch when RECEIVING 487, not when SENDING it.",
                        'error_frame': err_msg.frame_num,
                        'error_timestamp': err_timestamp,
                        'switch_frame': switch['frame'],
                        'switch_timestamp': switch['timestamp'],
                        'time_diff_ms': time_diff * 1000
                    })

    return results


def print_results(results: Dict, messages: List[STUNMessage], server_ip: str):
    """Print validation results in a readable format"""
    print("\n" + "="*80)
    print("RFC 8445 VALIDATION RESULTS")
    print("="*80)

    # Summary
    print("\n## Summary")
    print(f"Total STUN Binding Requests analyzed: {sum(1 for m in messages if m.is_binding_request())}")
    print(f"Role conflicts detected: {len(results['conflicts'])}")
    print(f"Error 487 responses: {results['error_487_count']}")
    print(f"Client role switches: {sum(1 for s in results['role_switches'] if s['endpoint'] == 'client')}")
    print(f"Server role switches: {sum(1 for s in results['role_switches'] if s['endpoint'] == 'server')}")
    print(f"RFC violations: {len(results['violations'])}")

    # Tie-breaker values
    print("\n## Tie-Breaker Values")
    if results['client_tie_breaker']:
        print(f"Client tie-breaker: {results['client_tie_breaker']} (0x{results['client_tie_breaker']:016x})")
    else:
        print("Client tie-breaker: Not found")

    if results['server_tie_breaker']:
        print(f"Server tie-breaker: {results['server_tie_breaker']} (0x{results['server_tie_breaker']:016x})")
    else:
        print("Server tie-breaker: Not found")

    if results['client_tie_breaker'] and results['server_tie_breaker']:
        print(f"\nComparison: ", end="")
        if results['client_tie_breaker'] > results['server_tie_breaker']:
            print(f"Client > Server (client wins conflict)")
        elif results['client_tie_breaker'] < results['server_tie_breaker']:
            print(f"Server > Client (server wins conflict)")
        else:
            print(f"Equal (should not happen!)")

    # Violations
    if results['violations']:
        print("\n## ⚠️  RFC 8445 VIOLATIONS DETECTED")
        for v in results['violations']:
            if v['type'] == 'TIE_BREAKER_CHANGED':
                ts = datetime.fromtimestamp(v['timestamp']).strftime('%H:%M:%S.%f')[:-3]
                print(f"\n❌ Frame {v['frame']} @ {ts}")
                print(f"   {v['message']}")
            elif v['type'] == 'MISSING_487_RESPONSE':
                print(f"\n❌ {v['endpoint'].upper()} RFC 8445 Section 7.3.1.1 Violation:")
                print(f"   {v['message']}")
                print(f"   Required: {v['required']} | Actual: {v['actual']} | Missing: {v['missing']}")
            elif v['type'] == 'IMPROPER_ROLE_SWITCH_AFTER_SENDING_487':
                err_ts = datetime.fromtimestamp(v['error_timestamp']).strftime('%H:%M:%S.%f')[:-3]
                switch_ts = datetime.fromtimestamp(v['switch_timestamp']).strftime('%H:%M:%S.%f')[:-3]
                print(f"\n❌ {v['endpoint'].upper()} RFC 8445 Section 7.3.1.1 Violation:")
                print(f"   {v['message']}")
                print(f"   Sent 487 at {err_ts} (frame {v['error_frame']})")
                print(f"   Switched role at {switch_ts} (frame {v['switch_frame']})")
                print(f"   Time difference: {v['time_diff_ms']:.1f}ms")
    else:
        print("\n## ✅ No RFC violations detected")

    # Role switches
    if results['role_switches']:
        print("\n## Role Transitions")
        for switch in results['role_switches']:
            ts = datetime.fromtimestamp(switch['timestamp']).strftime('%H:%M:%S.%f')[:-3]
            endpoint = switch['endpoint'].capitalize()
            print(f"  {ts} | {endpoint:6s} | {switch['old_role']:11s} → {switch['new_role']:11s} | Frame {switch['frame']}")

    # Conflicts
    if results['conflicts']:
        print("\n## Role Conflicts Detected")
        print(f"\nTotal conflicts: {len(results['conflicts'])}")

        # Show summary of who should send 487s
        server_should_send = sum(1 for c in results['conflicts'] if c.get('should_send_487') == 'server')
        client_should_send = sum(1 for c in results['conflicts'] if c.get('should_send_487') == 'client')

        if server_should_send > 0:
            print(f"Server should send 487: {server_should_send} conflicts")
        if client_should_send > 0:
            print(f"Client should send 487: {client_should_send} conflicts")

        # Only show first 10 conflicts in detail to avoid overwhelming output
        print(f"\nShowing first 10 conflicts (use script to see all):")
        for conflict in results['conflicts'][:10]:
            ts = datetime.fromtimestamp(conflict['timestamp']).strftime('%H:%M:%S.%f')[:-3]
            print(f"\n⚠️  Frame {conflict['frame']} @ {ts}")
            print(f"   Both sides in {conflict['role']} role")
            print(f"   Client tie-breaker: {conflict['client_tie_breaker']}")
            print(f"   Server tie-breaker: {conflict['server_tie_breaker']}")

            # RFC 8445 Section 7.3.1.1: Logic depends on role
            if conflict['client_tie_breaker'] and conflict['server_tie_breaker']:
                if conflict['role'] == 'CONTROLLING':
                    # Both CONTROLLING: higher/equal tie-breaker sends 487
                    if conflict['client_tie_breaker'] >= conflict['server_tie_breaker']:
                        print(f"   RFC 8445: Client should send 487 (both CONTROLLING, client >= server)")
                    else:
                        print(f"   RFC 8445: Server should send 487 (both CONTROLLING, server > client)")
                else:  # Both CONTROLLED
                    # Both CONTROLLED: lower tie-breaker sends 487
                    if conflict['client_tie_breaker'] < conflict['server_tie_breaker']:
                        print(f"   RFC 8445: Client should send 487 (both CONTROLLED, client < server)")
                    else:
                        print(f"   RFC 8445: Server should send 487 (both CONTROLLED, server <= client)")

        if len(results['conflicts']) > 10:
            print(f"\n... and {len(results['conflicts']) - 10} more conflicts")

    # 487 Errors
    if results['error_487_messages']:
        print("\n## STUN Error 487 (Role Conflict) Messages")
        for err in results['error_487_messages']:
            ts = datetime.fromtimestamp(err.timestamp).strftime('%H:%M:%S.%f')[:-3]
            direction = err.direction(server_ip)
            print(f"  {ts} | {direction:15s} | Frame {err.frame_num} | TxID: {err.transaction_id}")

    print("\n" + "="*80)


def main():
    parser = argparse.ArgumentParser(
        description='Validate RFC 8445 ICE role conflict resolution in pcap files'
    )
    parser.add_argument('input_file', help='Input file (pcap or JSON)')
    parser.add_argument('--format', choices=['pcap', 'json'], default='pcap',
                       help='Input file format (default: pcap)')
    parser.add_argument('--server-ip', required=True,
                       help='Server IP address to distinguish client/server')
    parser.add_argument('--server-port', default='8443',
                       help='Server port (default: 8443)')

    args = parser.parse_args()

    # Convert pcap to JSON if needed
    if args.format == 'pcap':
        json_file = export_pcap_to_json(args.input_file)
    else:
        json_file = args.input_file

    # Parse messages
    print(f"\nParsing STUN messages from {json_file}...")
    messages = parse_json_packets(json_file, args.server_ip)
    print(f"Found {len(messages)} STUN messages")

    # Validate RFC 8445 compliance
    print("\nValidating RFC 8445 Section 7.3.1.1 compliance...")
    results = validate_rfc8445(messages, args.server_ip)

    # Print results
    print_results(results, messages, args.server_ip)


if __name__ == '__main__':
    main()
