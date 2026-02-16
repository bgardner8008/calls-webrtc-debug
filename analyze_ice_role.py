#!/usr/bin/env python3
"""
WebRTC Call Analyzer v2 - Uses tshark for reliable STUN parsing
"""

import argparse
import re
import sys
import subprocess
from datetime import datetime
from typing import List, Dict, Optional

class Event:
    def __init__(self, timestamp: Optional[float], source: str, direction: str,
                 event_type: str, details: str, raw_data: dict = None):
        self.timestamp = timestamp
        self.source = source
        self.direction = direction
        self.event_type = event_type
        self.details = details
        self.raw_data = raw_data or {}

    def __repr__(self):
        if self.timestamp:
            ts_str = datetime.fromtimestamp(self.timestamp).strftime('%H:%M:%S.%f')[:-3]
        else:
            ts_str = "??:??:??.???"
        return f"{ts_str} [{self.source:4}] {self.direction:15} {self.event_type:15} {self.details}"

    def log_repr(self):
        """Representation for log events with line numbers instead of timestamps"""
        line_num = self.raw_data.get('line_num', '?') if self.raw_data else '?'
        return f"Line {line_num:4} {self.direction:15} {self.event_type:15} {self.details}"

class LogParser:
    """Parse browser console logs for SDP signaling and ICE state changes"""

    def __init__(self, log_file: str):
        self.log_file = log_file
        with open(log_file, 'r') as f:
            self.lines = f.readlines()
        self.has_timestamps = self._detect_timestamps()
        self.client_endpoints = self._extract_client_endpoints()

    def _detect_timestamps(self) -> bool:
        """Detect if log file has Chrome console timestamps (HH:MM:SS.mmm format)"""
        for line in self.lines[:10]:  # Check first 10 lines
            # Chrome console timestamp format: HH:MM:SS.mmm at start of line
            if re.match(r'^\d{2}:\d{2}:\d{2}\.\d{3}', line):
                return True
        return False

    def _extract_timestamp(self, line: str) -> Optional[float]:
        """Extract timestamp from Chrome console log line if present"""
        match = re.match(r'^(\d{2}):(\d{2}):(\d{2})\.(\d{3})', line)
        if match:
            hours = int(match.group(1))
            minutes = int(match.group(2))
            seconds = int(match.group(3))
            millis = int(match.group(4))
            # Convert to seconds since midnight (relative timestamp)
            # Use reference_date if available, otherwise today
            from datetime import datetime, date
            ref_date = getattr(self, 'reference_date', None) or date.today()
            dt = datetime(ref_date.year, ref_date.month, ref_date.day, hours, minutes, seconds, millis * 1000)
            return dt.timestamp()
        return None

    def _extract_client_endpoints(self) -> List[str]:
        """Extract all client-side endpoints (IP:port) from ICE candidates in log

        Only extracts LOCAL candidates (from onICECandidate), not remote candidates
        (from handling remote signaling data). This ensures we only track STUN messages
        for the specific client that generated this log file.

        Returns list of unique "IP:port" strings used by this client.
        """
        endpoints = set()
        for line in self.lines:
            # Only process lines that contain LOCAL ICE candidates
            # Skip lines with "handling remote signaling data" which are from the remote peer
            if 'handling remote signaling data' in line or 'remote' in line.lower():
                continue

            # Look for local candidate indicators
            if 'onICECandidate' not in line and 'local candidate' not in line and 'makeOffer' not in line and 'generated local answer' not in line:
                continue

            # Match ICE candidate format: "candidate:... IP PORT typ TYPE..."
            # Example: "candidate:2138392041 1 udp 2121801471 172.16.0.11 65483 typ host..."
            matches = re.findall(r'candidate:\S+\s+\d+\s+\w+\s+\d+\s+([\d.]+)\s+(\d+)\s+typ\s+(\w+)', line)
            for ip, port, typ in matches:
                # Only include host and srflx (server reflexive) candidates
                # These represent the client's actual endpoints
                # Skip server port 8443 to avoid confusion
                if typ in ['host', 'srflx'] and port != '8443':
                    endpoints.add(f"{ip}:{port}")

        result = sorted(endpoints)
        if result:
            print(f"Detected client endpoints from log: {result}", file=sys.stderr)
        return result

    def parse(self) -> List[Event]:
        """Parse log file for WebRTC events"""
        events = []

        for line_num, line in enumerate(self.lines, 1):
            if 'handling remote signaling data' in line:
                event = self._parse_sdp_remote(line, line_num)
                if event:
                    events.append(event)
            elif 'RTCPeer.signal: sending' in line or 'makeOffer' in line or 'generated local answer' in line:
                event = self._parse_sdp_local(line, line_num)
                if event:
                    events.append(event)
            elif 'ICE connection state change' in line:
                event = self._parse_ice_state(line, line_num)
                if event:
                    events.append(event)
            elif 'connection state change' in line and 'ICE' not in line:
                event = self._parse_connection_state(line, line_num)
                if event:
                    events.append(event)

        return events

    def _parse_sdp_remote(self, line: str, line_num: int) -> Optional[Event]:
        try:
            json_match = re.search(r'\{"type":', line)
            if not json_match:
                return None

            import json
            json_str = line[json_match.start():].split('\n')[0].rstrip()
            data = json.loads(json_str)
            sdp_type = data.get('type', 'unknown')
            sdp = data.get('sdp', '')

            setup_match = re.search(r'a=setup:(\w+)', sdp)
            setup = setup_match.group(1) if setup_match else 'unknown'

            ufrag_match = re.search(r'a=ice-ufrag:(\S+)', sdp)
            ufrag = ufrag_match.group(1) if ufrag_match else None

            event_type = f"SDP_{sdp_type.upper()}"
            details = f"setup:{setup}"
            if ufrag:
                details += f" ufrag:{ufrag[:8]}..."

            # Extract timestamp if available
            timestamp = self._extract_timestamp(line) if self.has_timestamps else None

            return Event(
                timestamp=timestamp,
                source='LOG',
                direction='Server→Client',
                event_type=event_type,
                details=details,
                raw_data={'line_num': line_num, 'setup': setup, 'ufrag': ufrag}
            )
        except Exception as e:
            print(f"Error parsing SDP at line {line_num}: {e}", file=sys.stderr)
            return None

    def _parse_sdp_local(self, line: str, line_num: int) -> Optional[Event]:
        # Extract timestamp if available
        timestamp = self._extract_timestamp(line) if self.has_timestamps else None

        if 'makeOffer' in line:
            # Try to extract actual SDP from JSON
            setup = 'actpass'
            ufrag = None
            json_match = re.search(r'\{"type":', line)
            if json_match:
                try:
                    import json
                    json_str = line[json_match.start():].split('\n')[0].rstrip()
                    data = json.loads(json_str)
                    sdp = data.get('sdp', '')

                    setup_match = re.search(r'a=setup:(\w+)', sdp)
                    setup = setup_match.group(1) if setup_match else 'actpass'

                    ufrag_match = re.search(r'a=ice-ufrag:(\S+)', sdp)
                    ufrag = ufrag_match.group(1) if ufrag_match else None
                except:
                    pass

            details = f"setup:{setup}"
            if ufrag:
                details += f" ufrag:{ufrag[:8]}..."

            return Event(
                timestamp=timestamp,
                source='LOG',
                direction='Client→Server',
                event_type='SDP_OFFER',
                details=details,
                raw_data={'line_num': line_num, 'setup': setup, 'ufrag': ufrag}
            )
        elif 'generated local answer' in line:
            # Parse the actual answer SDP from JSON
            setup = 'passive'
            ufrag = None
            json_match = re.search(r'\{"type":"answer"', line)
            if json_match:
                try:
                    import json
                    json_str = line[json_match.start():].split('\n')[0].rstrip()
                    data = json.loads(json_str)
                    sdp = data.get('sdp', '')

                    setup_match = re.search(r'a=setup:(\w+)', sdp)
                    setup = setup_match.group(1) if setup_match else 'passive'

                    ufrag_match = re.search(r'a=ice-ufrag:(\S+)', sdp)
                    ufrag = ufrag_match.group(1) if ufrag_match else None
                except:
                    pass

            details = f"setup:{setup}"
            if ufrag:
                details += f" ufrag:{ufrag[:8]}..."

            return Event(
                timestamp=timestamp,
                source='LOG',
                direction='Client→Server',
                event_type='SDP_ANSWER',
                details=details,
                raw_data={'line_num': line_num, 'setup': setup, 'ufrag': ufrag}
            )
        return None

    def _parse_ice_state(self, line: str, line_num: int) -> Optional[Event]:
        match = re.search(r'ICE connection state change -> (\w+)', line)
        if match:
            state = match.group(1)
            # Extract timestamp if available
            timestamp = self._extract_timestamp(line) if self.has_timestamps else None
            return Event(
                timestamp=timestamp,
                source='LOG',
                direction='N/A',
                event_type='ICE_STATE',
                details=f"→ {state}",
                raw_data={'line_num': line_num, 'state': state}
            )
        return None

    def _parse_connection_state(self, line: str, line_num: int) -> Optional[Event]:
        match = re.search(r'connection state change -> (\w+)', line)
        if match:
            state = match.group(1)
            # Extract timestamp if available
            timestamp = self._extract_timestamp(line) if self.has_timestamps else None
            return Event(
                timestamp=timestamp,
                source='LOG',
                direction='N/A',
                event_type='CONN_STATE',
                details=f"→ {state}",
                raw_data={'line_num': line_num, 'state': state}
            )
        return None


def extract_client_ips_from_server_log(log_file: str) -> List[str]:
    """Extract client IP addresses from Pion ICE server logs

    Looks for patterns like:
    - "Found valid candidate pair: ... -> IP:PORT"
    - "Inbound STUN (Request) from IP:PORT"
    - "Set selected pair: ... -> IP:PORT"

    Returns list of unique client IP addresses found in the logs.
    """
    ips = set()

    with open(log_file, 'r') as f:
        for line in f:
            # Match candidate pair logs: "... -> IP:PORT" or "... from IP:PORT"
            # Example: "Found valid candidate pair: 192.168.64.1:8443 -> 192.168.64.1:61775"
            # Example: "Inbound STUN (Request) from 127.0.0.1:56789 to 127.0.0.1:8443"

            # Pattern 1: "-> IP:PORT" (remote candidate in pair)
            matches = re.findall(r'->\s*([\d.]+):\d+', line)
            ips.update(matches)

            # Pattern 2: "from IP:PORT" (STUN messages)
            matches = re.findall(r'from\s+([\d.]+):\d+', line)
            ips.update(matches)

            # Pattern 3: ICE candidate parsing - extract IPs that aren't 127.0.0.1 or 0.0.0.0
            matches = re.findall(r'candidate:\S+\s+\d+\s+\w+\s+\d+\s+([\d.]+)\s+\d+\s+typ', line)
            for ip in matches:
                if ip not in ['127.0.0.1', '0.0.0.0']:
                    ips.add(ip)

    result = sorted(ips)
    if result:
        print(f"Extracted client IPs from server log: {result}", file=sys.stderr)
    return result


class TsharkPcapParser:
    """Parse pcap files using tshark for accurate STUN parsing"""

    def __init__(self, pcap_file: str, client_endpoints: Optional[List[str]] = None,
                 client_ips: Optional[List[str]] = None, server_ip: Optional[str] = None,
                 server_port: int = 8443, selected_only: bool = False):
        self.pcap_file = pcap_file
        self.server_port = server_port
        self.server_ip = server_ip
        self.client_ips = client_ips or []
        self.client_endpoints = client_endpoints or []
        self.selected_only = selected_only

    def parse(self) -> List[Event]:
        events = []

        # If selected_only mode, identify the most active endpoint first
        if self.selected_only and self.client_endpoints:
            selected_endpoint = self._find_selected_endpoint()
            if selected_endpoint:
                print(f"Selected candidate pair (most active): {selected_endpoint}", file=sys.stderr)
                self.client_endpoints = [selected_endpoint]
            else:
                print("Warning: Could not identify selected candidate pair, showing all endpoints", file=sys.stderr)

        # Get STUN role messages
        events.extend(self._parse_stun_roles())

        # Get STUN errors
        events.extend(self._parse_stun_errors())

        return sorted(events, key=lambda e: e.timestamp or 0)

    def _find_selected_endpoint(self) -> Optional[str]:
        """Find the most active client endpoint based on UDP packet count

        Counts all UDP packets (excluding STUN) to/from each client endpoint.
        The endpoint with the most traffic is likely the selected candidate pair.
        """
        try:
            # Build filter for all UDP packets to/from server port (excluding STUN)
            # We want to count media/data packets, not STUN keepalives
            udp_filter = f'udp.port == {self.server_port} and not stun'

            cmd = [
                '/usr/local/bin/tshark',
                '-r', self.pcap_file,
                '-Y', udp_filter,
                '-T', 'fields',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-E', 'separator=|'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                return None

            # Count packets per client endpoint
            endpoint_counts = {}

            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue

                parts = line.split('|')
                if len(parts) < 4:
                    continue

                src_ip = parts[0]
                dst_ip = parts[1]
                src_port = parts[2]
                dst_port = parts[3]

                # Identify client endpoint (the non-8443 side)
                if src_port == str(self.server_port):
                    client_endpoint = f"{dst_ip}:{dst_port}"
                elif dst_port == str(self.server_port):
                    client_endpoint = f"{src_ip}:{src_port}"
                else:
                    continue

                # Only count endpoints we're tracking
                if client_endpoint in self.client_endpoints:
                    endpoint_counts[client_endpoint] = endpoint_counts.get(client_endpoint, 0) + 1

            # Return the endpoint with the most packets
            if endpoint_counts:
                selected = max(endpoint_counts.items(), key=lambda x: x[1])
                print(f"UDP packet counts: {dict(sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True))}", file=sys.stderr)
                return selected[0]

            return None

        except Exception as e:
            print(f"Error finding selected endpoint: {e}", file=sys.stderr)
            return None

    def _parse_stun_roles(self) -> List[Event]:
        """Parse STUN Binding Requests with ICE role attributes using tshark

        Only Binding Requests (method 0x0001) are analyzed because:
        - Only Binding Requests trigger handleRoleConflict() for conflict detection
        - Role attributes in Success/Error Responses don't affect ICE role negotiation
        """
        events = []

        try:
            # Build filter for STUN Binding Requests with role attributes
            # stun.type == 0x0001 = Binding Request (method + class)
            # stun.att.type == 0x8029 = ICE-CONTROLLED attribute
            # stun.att.type == 0x802a = ICE-CONTROLLING attribute
            stun_filter = 'stun.type == 0x0001 and (stun.att.type == 0x8029 or stun.att.type == 0x802a)'

            # Filter by client IPs if specified (for backwards compatibility with server logs)
            if self.client_ips:
                ip_filters = [f'(ip.addr == {ip})' for ip in self.client_ips]
                ip_filter = ' or '.join(ip_filters)
                stun_filter = f'({stun_filter}) and ({ip_filter})'

            cmd = [
                '/usr/local/bin/tshark',
                '-r', self.pcap_file,
                '-Y', stun_filter,
                '-T', 'fields',
                '-e', 'frame.time_epoch',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-e', 'stun.att.type',
                '-E', 'separator=|'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"tshark error: {result.stderr}", file=sys.stderr)
                return events

            # Track roles per unique endpoint and direction
            # The role attribute in STUN indicates the SENDER's role, so:
            # - Client→Server messages show the client's role
            # - Server→Client messages show the server's role
            # We need to track these separately to avoid false transitions
            client_roles = {}  # Key: endpoint, Value: client's current role
            server_roles = {}  # Key: endpoint, Value: server's current role

            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue

                parts = line.split('|')
                if len(parts) < 6:
                    continue

                timestamp = float(parts[0])
                src_ip = parts[1]
                dst_ip = parts[2]
                src_port = parts[3]
                dst_port = parts[4]
                att_types = parts[5]  # Comma-separated attribute types

                # Identify client and server endpoints based on port 8443
                # Server is always at port 8443
                if src_port == str(self.server_port):
                    direction = 'Server→Client'
                    sender = 'server'
                    client_endpoint = f"{dst_ip}:{dst_port}"
                    server_endpoint = f"{src_ip}:{src_port}"
                elif dst_port == str(self.server_port):
                    direction = 'Client→Server'
                    sender = 'client'
                    client_endpoint = f"{src_ip}:{src_port}"
                    server_endpoint = f"{dst_ip}:{dst_port}"
                else:
                    continue

                # Filter by client endpoints if specified (from log file ICE candidates)
                # This filters out STUN messages to/from other clients
                if self.client_endpoints and client_endpoint not in self.client_endpoints:
                    continue

                # Determine role from attribute types (comma-separated)
                # ICE-CONTROLLING = 0x802a, ICE-CONTROLLED = 0x8029
                # The role attribute indicates the SENDER's role
                if '0x802a' in att_types:
                    role = 'CONTROLLING'
                elif '0x8029' in att_types:
                    role = 'CONTROLLED'
                else:
                    continue

                # Get current role state for the appropriate side
                if sender == 'client':
                    current_role_state = client_roles.get(client_endpoint)
                    role_dict = client_roles
                    side_label = 'Client'
                else:  # sender == 'server'
                    current_role_state = server_roles.get(client_endpoint)
                    role_dict = server_roles
                    side_label = 'Server'

                # Check for initial or transition
                if current_role_state is None:
                    events.append(Event(
                        timestamp=timestamp,
                        source='PCAP',
                        direction=direction,
                        event_type='STUN_INITIAL',
                        details=f"{side_label} ICE role: {role} [{client_endpoint}]"
                    ))
                    role_dict[client_endpoint] = role

                elif current_role_state != role:
                    events.append(Event(
                        timestamp=timestamp,
                        source='PCAP',
                        direction=direction,
                        event_type='STUN_TRANSITION',
                        details=f"{side_label} ICE role: {current_role_state} → {role} [{client_endpoint}]"
                    ))
                    role_dict[client_endpoint] = role

        except Exception as e:
            print(f"Error parsing STUN roles: {e}", file=sys.stderr)

        return events

    def _parse_stun_errors(self) -> List[Event]:
        """Parse STUN error responses using tshark"""
        events = []

        try:
            # Build filter for STUN error 487
            error_filter = 'stun.att.error == 87'

            # Filter by client IPs if specified (for backwards compatibility with server logs)
            if self.client_ips:
                ip_filters = [f'(ip.addr == {ip})' for ip in self.client_ips]
                ip_filter = ' or '.join(ip_filters)
                error_filter = f'({error_filter}) and ({ip_filter})'

            cmd = [
                '/usr/local/bin/tshark',
                '-r', self.pcap_file,
                '-Y', error_filter,
                '-T', 'fields',
                '-e', 'frame.time_epoch',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'udp.srcport',
                '-e', 'udp.dstport',
                '-e', 'stun.att.error',
                '-e', 'stun.att.error.reason',
                '-E', 'separator=|'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                print(f"tshark error: {result.stderr}", file=sys.stderr)
                return events

            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue

                parts = line.split('|')
                if len(parts) < 6:
                    continue

                timestamp = float(parts[0])
                src_ip = parts[1]
                dst_ip = parts[2]
                src_port = parts[3]
                dst_port = parts[4]
                error_code = parts[5]
                error_reason = parts[6] if len(parts) > 6 else ''

                # Identify client and server endpoints based on port 8443
                if src_port == str(self.server_port):
                    direction = 'Server→Client'
                    client_endpoint = f"{dst_ip}:{dst_port}"
                elif dst_port == str(self.server_port):
                    direction = 'Client→Server'
                    client_endpoint = f"{src_ip}:{src_port}"
                else:
                    direction = 'Unknown'
                    client_endpoint = f"{src_ip}:{src_port}"

                # Filter by client endpoints if specified (from log file ICE candidates)
                if self.client_endpoints and client_endpoint not in self.client_endpoints:
                    continue

                events.append(Event(
                    timestamp=timestamp,
                    source='PCAP',
                    direction=direction,
                    event_type='STUN_ERROR_487',
                    details=f'Role Conflict Error [{client_endpoint}]'
                ))

        except Exception as e:
            print(f"Error parsing STUN errors: {e}", file=sys.stderr)

        return events

class CallAnalyzer:
    """Correlate log and pcap events into unified timeline"""

    def __init__(self, log_file: Optional[str] = None, pcap_file: Optional[str] = None,
                 client_ips: Optional[List[str]] = None, server_ip: Optional[str] = None,
                 server_port: int = 8443, selected_only: bool = False):
        self.log_file = log_file
        self.pcap_file = pcap_file
        self.client_ips = client_ips
        self.server_ip = server_ip
        self.server_port = server_port
        self.selected_only = selected_only
        self.log_parser = None
        self.pcap_parser = None

    def analyze(self) -> tuple[List[Event], List[Event]]:
        """Parse files and return separate event lists"""
        from datetime import datetime

        # Parse PCAP first to get reference date for log timestamps
        reference_date = None
        client_endpoints = []

        if self.log_file:
            # Create initial log parser to extract client endpoints
            temp_log_parser = LogParser(self.log_file)
            client_endpoints = temp_log_parser._extract_client_endpoints()

        if self.pcap_file:
            self.pcap_parser = TsharkPcapParser(
                self.pcap_file,
                client_endpoints=client_endpoints,
                client_ips=self.client_ips,
                server_ip=self.server_ip,
                server_port=self.server_port,
                selected_only=self.selected_only
            )
            pcap_events = self.pcap_parser.parse()

            # Extract reference date from first PCAP event
            if pcap_events and pcap_events[0].timestamp:
                reference_date = datetime.fromtimestamp(pcap_events[0].timestamp).date()
        else:
            pcap_events = []

        # Now parse log with reference date
        if self.log_file:
            self.log_parser = LogParser(self.log_file)
            if reference_date:
                self.log_parser.reference_date = reference_date
            log_events = self.log_parser.parse()
        else:
            log_events = []

        return log_events, pcap_events

def main():
    parser = argparse.ArgumentParser(
        description='WebRTC Call Analyzer - Analyze browser logs and/or packet captures',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --log call3.log --pcap call3.pcap    # Analyze both
  %(prog)s --log call3.log                       # Analyze log only
  %(prog)s --pcap call3.pcap                     # Analyze pcap only
  %(prog)s --pcap call.pcap --server-log server.log  # Auto-detect client IPs from server log
        '''
    )
    parser.add_argument('--log', type=str, help='Browser console log file (client-side)')
    parser.add_argument('--pcap', type=str, help='Packet capture file')
    parser.add_argument('--server-log', type=str, help='Server log file (Pion ICE logs) - used to auto-detect client IPs')
    parser.add_argument('--server-ip', type=str, help='Server IP address (auto-detected from pcap if not specified)')
    parser.add_argument('--server-port', type=int, default=8443, help='Server port (default: 8443)')
    parser.add_argument('--selected-only', action='store_true',
                       help='Only show the selected candidate pair (most active endpoint based on UDP traffic)')

    args = parser.parse_args()

    # Require at least one input
    if not args.log and not args.pcap:
        parser.error("At least one of --log or --pcap is required")

    # Extract client IPs from server log if provided
    client_ips = []
    if args.server_log:
        client_ips = extract_client_ips_from_server_log(args.server_log)
        if client_ips:
            print(f"Auto-detected client IPs: {client_ips}", file=sys.stderr)
            print(f"Will filter STUN packets to/from these IPs", file=sys.stderr)
            print()

    # Print header
    files = []
    if args.log:
        files.append(f"log: {args.log}")
    if args.pcap:
        files.append(f"pcap: {args.pcap}")

    print(f"Analyzing {', '.join(files)}...")
    print("=" * 100)
    print()

    # Analyze
    analyzer = CallAnalyzer(
        log_file=args.log,
        pcap_file=args.pcap,
        client_ips=client_ips if client_ips else None,
        server_ip=args.server_ip,
        server_port=args.server_port,
        selected_only=args.selected_only
    )
    log_events, pcap_events = analyzer.analyze()

    # Check if log events have timestamps
    log_has_timestamps = log_events and any(e.timestamp is not None for e in log_events)

    # If both sources have timestamps, show unified timeline
    if log_has_timestamps and pcap_events:
        print("=== Unified Timeline (Browser Log + Network Capture) ===")
        print()
        all_events = sorted(log_events + pcap_events, key=lambda e: e.timestamp or 0)
        for event in all_events:
            print(event)
        print()
        print("=" * 100)
        print()
    else:
        # Show separately if logs don't have timestamps
        # Print PCAP events if requested
        if args.pcap and pcap_events:
            print("=== PCAP Events (Real Timestamps from Network Capture) ===")
            print()
            for event in pcap_events:
                print(event)
            print()
            print("=" * 100)
            print()

        # Print LOG events if requested
        if args.log and log_events:
            if log_has_timestamps:
                print("=== Browser Log Events (with Timestamps) ===")
                print()
                for event in log_events:
                    print(event)
            else:
                print("=== Browser Log Events (Sequential Order - No Timestamps Available) ===")
                print()
                for event in log_events:
                    print(event.log_repr())
            print()
            print("=" * 100)
            print()

    # Summary statistics
    if args.pcap or args.log:
        stun_transitions = [e for e in pcap_events if e.event_type == 'STUN_TRANSITION']
        ice_disconnects = [e for e in log_events if e.event_type == 'ICE_STATE' and 'disconnected' in e.details]
        stun_errors = [e for e in pcap_events if 'ERROR' in e.event_type]

        if args.pcap:
            print(f"Total PCAP events: {len(pcap_events)}")
        if args.log:
            print(f"Total LOG events: {len(log_events)}")
            if log_has_timestamps:
                print(f"Log timestamps: ✓ Detected")
            else:
                print(f"Log timestamps: ✗ Not found (enable in Chrome: Settings → Console → Show timestamps)")
        if args.pcap:
            print(f"STUN role transitions: {len(stun_transitions)}")
        if args.log:
            print(f"ICE disconnects: {len(ice_disconnects)}")
        if args.pcap:
            print(f"STUN errors: {len(stun_errors)}")

        if stun_errors and args.pcap:
            print()
            print("STUN Error Details:")
            for err in stun_errors:
                print(f"  - {err.direction} at {datetime.fromtimestamp(err.timestamp).strftime('%H:%M:%S.%f')[:-3]}: {err.details}")

if __name__ == '__main__':
    main()
