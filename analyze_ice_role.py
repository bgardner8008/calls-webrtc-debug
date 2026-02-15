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
        self.client_ports = self._extract_client_ports()

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

    def _extract_client_ports(self) -> List[int]:
        """Extract all client-side ports from ICE candidates in log

        This handles multiple clients on same machine and ICE restarts.
        Returns list of unique port numbers used by this client.
        """
        ports = set()
        for line in self.lines:
            # Match ICE candidate format: "candidate:... IP PORT typ TYPE..."
            # Example: "candidate:2138392041 1 udp 2121801471 172.16.0.11 65483 typ host..."
            matches = re.findall(r'candidate:\S+\s+\d+\s+\w+\s+\d+\s+([\d.]+)\s+(\d+)\s+typ\s+(\w+)', line)
            for ip, port, typ in matches:
                # Only include host and srflx (server reflexive) candidates
                # These represent the client's actual ports
                if typ in ['host', 'srflx']:
                    ports.add(int(port))

        result = sorted(ports)
        if result:
            print(f"Detected client ports from log: {result}", file=sys.stderr)
        return result

    def parse(self) -> List[Event]:
        events = []

        for line_num, line in enumerate(self.lines, 1):
            if 'handling remote signaling data' in line:
                event = self._parse_sdp_remote(line, line_num)
                if event:
                    events.append(event)
            elif 'RTCPeer.signal: sending' in line or 'makeOffer' in line:
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
        elif 'sending answer' in line:
            return Event(
                timestamp=timestamp,
                source='LOG',
                direction='Client→Server',
                event_type='SDP_ANSWER',
                details='setup:passive (typical)',
                raw_data={'line_num': line_num}
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

class TsharkPcapParser:
    """Parse pcap files using tshark for accurate STUN parsing"""

    def __init__(self, pcap_file: str, client_ports: Optional[List[int]] = None):
        self.pcap_file = pcap_file
        self.server_port = 8443
        self.client_ports = client_ports or []

    def parse(self) -> List[Event]:
        events = []

        # Get STUN role messages
        events.extend(self._parse_stun_roles())

        # Get STUN errors
        events.extend(self._parse_stun_errors())

        return sorted(events, key=lambda e: e.timestamp or 0)

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

            # If client ports specified, filter to only those ports communicating with server
            if self.client_ports:
                port_filters = [f'(udp.port == {port} and udp.port == {self.server_port})'
                               for port in self.client_ports]
                port_filter = ' or '.join(port_filters)
                stun_filter = f'({stun_filter}) and ({port_filter})'

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

            # Track roles to detect transitions
            server_to_client_role = None
            client_to_server_role = None

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

                # Determine direction
                if src_port == str(self.server_port):
                    direction = 'Server→Client'
                    current_role_state = server_to_client_role
                elif dst_port == str(self.server_port):
                    direction = 'Client→Server'
                    current_role_state = client_to_server_role
                else:
                    continue

                # Determine role from attribute types (comma-separated)
                # ICE-CONTROLLING = 0x802a, ICE-CONTROLLED = 0x8029
                if '0x802a' in att_types:
                    role = 'CONTROLLING'
                elif '0x8029' in att_types:
                    role = 'CONTROLLED'
                else:
                    continue

                # Check for initial or transition
                if current_role_state is None:
                    events.append(Event(
                        timestamp=timestamp,
                        source='PCAP',
                        direction=direction,
                        event_type='STUN_INITIAL',
                        details=f"ICE role: {role}"
                    ))
                    if direction == 'Server→Client':
                        server_to_client_role = role
                    else:
                        client_to_server_role = role

                elif current_role_state != role:
                    events.append(Event(
                        timestamp=timestamp,
                        source='PCAP',
                        direction=direction,
                        event_type='STUN_TRANSITION',
                        details=f"ICE role: {current_role_state} → {role}"
                    ))
                    if direction == 'Server→Client':
                        server_to_client_role = role
                    else:
                        client_to_server_role = role

        except Exception as e:
            print(f"Error parsing STUN roles: {e}", file=sys.stderr)

        return events

    def _parse_stun_errors(self) -> List[Event]:
        """Parse STUN error responses using tshark"""
        events = []

        try:
            # Build filter for STUN error 487
            error_filter = 'stun.att.error == 87'

            # If client ports specified, filter to only those ports
            if self.client_ports:
                port_filters = [f'(udp.port == {port} and udp.port == {self.server_port})'
                               for port in self.client_ports]
                port_filter = ' or '.join(port_filters)
                error_filter = f'({error_filter}) and ({port_filter})'

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

                # Determine direction
                if src_port == str(self.server_port):
                    direction = 'Server→Client'
                elif dst_port == str(self.server_port):
                    direction = 'Client→Server'
                else:
                    direction = 'Unknown'

                events.append(Event(
                    timestamp=timestamp,
                    source='PCAP',
                    direction=direction,
                    event_type='STUN_ERROR_487',
                    details=f'Role Conflict Error'
                ))

        except Exception as e:
            print(f"Error parsing STUN errors: {e}", file=sys.stderr)

        return events

class CallAnalyzer:
    """Correlate log and pcap events into unified timeline"""

    def __init__(self, log_file: Optional[str] = None, pcap_file: Optional[str] = None):
        self.log_file = log_file
        self.pcap_file = pcap_file
        self.log_parser = None
        self.pcap_parser = None

    def analyze(self) -> tuple[List[Event], List[Event]]:
        """Parse files and return separate event lists"""
        from datetime import datetime

        # Parse PCAP first to get reference date for log timestamps
        reference_date = None
        client_ports = []

        if self.log_file:
            # Create initial log parser to extract client ports
            temp_log_parser = LogParser(self.log_file)
            client_ports = temp_log_parser.client_ports

        if self.pcap_file:
            self.pcap_parser = TsharkPcapParser(self.pcap_file, client_ports)
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
        '''
    )
    parser.add_argument('--log', type=str, help='Browser console log file')
    parser.add_argument('--pcap', type=str, help='Packet capture file')

    args = parser.parse_args()

    # Require at least one input
    if not args.log and not args.pcap:
        parser.error("At least one of --log or --pcap is required")

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
    analyzer = CallAnalyzer(log_file=args.log, pcap_file=args.pcap)
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
