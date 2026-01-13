#!/usr/local/ipcs/peon/venv/bin/python3
# -*- encoding: utf-8 -*-

##############################################################################
## Name: traceroute.py
## Purpose: UDP/ICMP traceroute with optional DNS/RTP payload in UDP.
## Date: 2026-01-12
## Author: sszokoly@protonmail.com
## License: MIT
## Version: 0.2
## Source: https://github.com/sszokoly/traceroute
##############################################################################

import array
import fcntl
import os
import select
import socket
import struct
import platform
import random
import time
from contextlib import ExitStack

try:
    import netifaces

    get_interface_names = netifaces.interfaces
except ModuleNotFoundError:

    def get_interface_names():
        max_interfaces = 128
        bytes_size = max_interfaces * 40  # Increased size for 64-bit
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        names = array.array("B", b"\0" * bytes_size)

        outbytes = struct.unpack(
            "iL",
            fcntl.ioctl(
                s.fileno(),
                0x8912,  # SIOCGIFCONF
                struct.pack("iL", bytes_size, names.buffer_info()[0]),
            ),
        )[0]

        namestr = names.tobytes()
        interfaces = []

        # Parse the structure more carefully
        i = 0
        while i < outbytes:
            name = namestr[i : i + 16].split(b"\0", 1)[0].decode("utf-8")
            if name:
                interfaces.append(name)
            i += 40  # Size of ifreq structure on 64-bit systems

        return [x for x in set(interfaces) if x]


try:
    import ipaddress

    def is_ip_address(addr):
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False

except ModuleNotFoundError:

    def is_ip_address(addr):
        try:
            socket.inet_aton(addr)
            return True
        except socket.error:
            return False


DEFAULT_COUNT_BYTE = 1024


class HopResult:
    def __init__(self, nqueries: int = 3):
        self.nqueries = nqueries
        self.count_of_success = 0
        self.response_times = []
        for _ in range(nqueries):
            self.response_times.append(0.0)
        self.hosts = []

    def add(self, query_num: int, value):
        self.response_times[query_num] = value
        self.count_of_success += 1

    def avg_response_time(self):
        sum_all = 0
        for value in self.response_times:
            sum_all += value
        if not self.count_of_success:
            return 0.0
        return sum_all / self.count_of_success


def create_icmp_packet(packet_id, sequence, packetlen=40):
    """Create an ICMP Echo Request packet."""
    # ICMP Echo Request: type=8, code=0
    icmp_type = 8
    icmp_code = 0
    checksum = 0

    # Pack header without checksum
    header = struct.pack(
        "!BBHHH", icmp_type, icmp_code, checksum, packet_id, sequence
    )
    data = b"A" * packetlen

    # Calculate checksum
    checksum = calculate_checksum(header + data)

    # Repack with correct checksum
    header = struct.pack(
        "!BBHHH", icmp_type, icmp_code, checksum, packet_id, sequence
    )
    return header + data


def create_dns_packet(domain="google.com", query_type=1, packetlen=172):
    """
    Create DNS query packet as bytes.

    Args:
        domain: Domain name to query (e.g., 'google.com')
        query_type: DNS query type (1=A, 28=AAAA, 15=MX, etc.)
        packetlen: Total packet length (IP + UDP + DNS)

    Returns:
        bytes: DNS query packet
    """
    # DNS Header (12 bytes)
    transaction_id = random.randint(0, 65535)
    flags = 0x0100  # Standard query, recursion desired
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        questions,
        answer_rrs,
        authority_rrs,
        additional_rrs,
    )

    # DNS Question Section
    # Encode domain name (e.g., 'google.com' -> '\x06google\x03com\x00')
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00"  # Null terminator

    # Query type and class
    question += struct.pack(
        "!HH", query_type, 1
    )  # Type, Class (1 = IN/Internet)

    dns_packet = header + question

    # Pad to reach desired packet length if needed
    # Total length = IP(20) + UDP(8) + DNS
    dns_size = len(dns_packet)
    desired_dns_size = packetlen - 20 - 8

    if dns_size < desired_dns_size:
        # Add padding (DNS allows additional data)
        padding = b"\x00" * (desired_dns_size - dns_size)
        dns_packet += padding

    return dns_packet


def create_rtp_packet(
    seq=0, timestamp=0, ssrc=0, payload_type=0, packetlen=172
):
    """Create RTP packet as bytes."""
    version = 2
    padding = 0
    extension = 0
    cc = 0
    marker = 0

    byte1 = (version << 6) | (padding << 5) | (extension << 4) | cc
    byte2 = (marker << 7) | (payload_type & 0x7F)

    rtp_header = struct.pack(
        "!BBHII", byte1, byte2, seq & 0xFFFF, timestamp, ssrc
    )

    # Calculate payload size (total - ETH - IP - UDP - RTP headers)
    payload_size = max(0, packetlen - 14 - 20 - 8 - 12)
    payload = b"\x00" * payload_size

    return rtp_header + payload


def calculate_checksum(data):
    """Calculate ICMP checksum."""
    if len(data) % 2:
        data += b"\x00"

    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def print_result(result: HopResult, dont_resolve: bool = False) -> None:
    output: list[str] = []

    for query_num in range(result.nqueries):
        response_time = result.response_times[query_num]
        if response_time is None:
            print(" *", end="")
            continue
        response_time_display = f"{response_time:>7} ms"
        current_host = result.hosts[query_num]
        previous_host = result.hosts[query_num - 1] if query_num > 0 else None

        # If duplicate host, only show response time
        if current_host == previous_host:
            response_time_display = f"{response_time:>7} ms"
            output.append(response_time_display)
            continue

        # Format host information
        if dont_resolve:
            host_display = current_host
        else:
            try:
                hostname = socket.gethostbyaddr(current_host)[0]
                host_display = f"{hostname} ({current_host})"
            except socket.herror:
                host_display = f"{current_host} ({current_host})"
        output.append(f" {host_display}{response_time_display}")
    print(" ".join(output))


def make_socket_udp(ttl, device=None, src_addr="0.0.0.0", sport=0):
    proto_u = socket.getprotobyname("udp")
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto_u)
    udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    # Bind to specific interface if provided
    if device:
        udp_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_BINDTODEVICE, device.encode()
        )

    udp_socket.bind((src_addr, sport))
    return udp_socket


def make_socket_icmp(ttl, port, device=None, src_addr="0.0.0.0", sport=0):
    proto_i = socket.getprotobyname("icmp")
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto_i)
    icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    # Only bind to device on Linux
    if device and platform.system() == "Linux":
        if device not in get_interface_names():
            raise OSError(
                f"setsockopt SO_BINDTODEVICE: No such device '{device}'"
            )
        icmp_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_BINDTODEVICE, device.encode()
        )
    elif device and platform.system() != "Linux":
        print(f"Warning: Device binding not supported on {platform.system()}")

    icmp_socket.bind((src_addr, port + ttl))
    return icmp_socket


def create_sockets(icmp, ttl, port, device, src_addr, sport):
    """Create send and receive sockets based on mode."""
    if icmp:
        sock: socket.socket = make_socket_icmp(
            ttl, port, device=device, src_addr=src_addr, sport=sport
        )
        return sock, sock
    else:
        send_sock: socket.socket = make_socket_udp(
            ttl, device=device, src_addr=src_addr, sport=sport
        )
        recv_sock: socket.socket = make_socket_icmp(
            ttl, port, device=device, src_addr=src_addr, sport=sport
        )
        return send_sock, recv_sock


def traceroute(
    host: str,
    port: int = 33434,
    max_ttl: int = 30,
    dont_resolve: bool = False,
    first_ttl: int = 1,
    device=None,
    src_addr: str = "0.0.0.0",
    sport: int = 0,
    nqueries: int = 3,
    icmp: bool = False,
    max_wait: float = 1.0,
    packetlen: int = 172,
    udp_format="rtp",
    dns_query="google.com",
    seq=0,
    timestamp=0,
    ssrc=3735928559,
    payload_type=0,
    no_inc_seq=False,
    no_inc_port=False,
    no_inc_timestamp=False,
    quiet=False,
) -> int:
    if not is_ip_address(host):
        resolved_host = socket.gethostbyname(host)
    else:
        resolved_host = host

    if not quiet:
        print(
            "traceroute to {} ({}), {} hops max, {} byte packets".format(
                host, resolved_host, max_ttl, packetlen
            )
        )

    for ttl in range(first_ttl, max_ttl + 1):
        cur = None
        result = HopResult(nqueries=nqueries)
        if not quiet:
            print(f"{ttl:>2} ", end="")

        for query_num in range(nqueries):
            send_socket, recv_socket = create_sockets(
                icmp, ttl, port, device, src_addr, sport
            )
            # Handle context managers
            if send_socket is recv_socket:
                sockets_to_close = [send_socket]
            else:
                sockets_to_close = [send_socket, recv_socket]

            with ExitStack() as stack:
                for sock in sockets_to_close:
                    stack.enter_context(sock)

                send_time = time.monotonic()

                if icmp:
                    # Send ICMP Echo Request
                    packet = create_icmp_packet(
                        packet_id=os.getpid() & 0xFFFF,
                        sequence=query_num,
                        packetlen=packetlen,
                    )
                elif udp_format == "rtp":
                    # Create RTP packet
                    packet = create_rtp_packet(
                        seq=seq,
                        timestamp=timestamp,
                        ssrc=ssrc,
                        payload_type=payload_type,
                        packetlen=packetlen,
                    )
                elif udp_format == "dns":
                    packet = create_dns_packet(
                        domain=dns_query,
                        query_type=1,  # A record
                        packetlen=packetlen,
                    )
                else:  # plain UDP
                    packet = (" " * (packetlen - 20 - 8)).encode()

                send_socket.sendto(packet, (resolved_host, port))
                if not no_inc_port:
                    port += 1  # Increment destination port in each packet

                ready, _, _ = select.select([recv_socket], [], [], max_wait)

                # Received no ICMP response
                if not ready:
                    result.hosts.append(None)
                    result.add(query_num, None)
                    continue

                # Received ICMP response
                data, cur = recv_socket.recvfrom(DEFAULT_COUNT_BYTE)
                recv_time = time.monotonic()
                cur = cur[0]
                result.hosts.append(cur)
                value = round((recv_time - send_time) * 1000, 3)
                result.add(query_num, value)

        if not no_inc_seq:
            seq += 1

        if not no_inc_timestamp:
            timestamp += 160

        if not quiet:
            print_result(result, dont_resolve)

        if cur == resolved_host:
            return 0

        if ttl == max_ttl:
            break

    return 1


if __name__ == "__main__":
    import argparse
    import sys

    # sys.argv.extend(['-q', '1', '-m', '1', '-I', '8.8.8.8'])

    class CustomHelpFormatter(argparse.HelpFormatter):
        def _format_action_invocation(self, action):
            if not action.option_strings:
                # Positional argument
                (metavar,) = self._metavar_formatter(action, action.dest)(1)
                return metavar
            else:
                parts = []
                # if the Optional doesn't take a value, format is: -s, --long
                if action.nargs == 0:
                    parts.extend(action.option_strings)
                # if the Optional takes a value, format is: -s ARGS, --long=ARGS
                else:
                    default = action.dest.upper()
                    args_string = self._format_args(action, default)
                    for option_string in action.option_strings:
                        if option_string.startswith("--"):
                            parts.append("%s=%s" % (option_string, args_string))
                        else:
                            parts.append("%s %s" % (option_string, args_string))
                return ", ".join(parts)

    parser = argparse.ArgumentParser(
        description="UDP/ICMP traceroute with optional DNS/RTP payload in UDP.",
        add_help=False,
        formatter_class=CustomHelpFormatter,
    )

    # Create custom groups in desired order
    optional = parser.add_argument_group("optional arguments")
    optional_dns = parser.add_argument_group("optional UDP/DNS arguments")
    optional_rtp = parser.add_argument_group("optional UDP/RTP arguments")
    positional = parser.add_argument_group("positional arguments")

    # Add help to optional arguments group
    optional.add_argument(
        "-h", "--help", action="help", help="show this help message and exit"
    )

    # Add all optional arguments to the optional group
    optional.add_argument(
        "-f",
        "--first",
        dest="first_ttl",
        type=int,
        default=1,
        metavar="first_ttl",
        help="Start from the first_ttl (not from 1)",
    )
    optional.add_argument(
        "-i",
        "--interface",
        dest="device",
        default=None,
        metavar="device",
        help="Specify a network interface to operate with",
    )
    optional.add_argument(
        "-I",
        "--icmp",
        dest="icmp",
        action="store_true",
        default=False,
        help="Use ICMP ECHO for tracerouting",
    )
    optional.add_argument(
        "-m",
        "--max-hops",
        dest="max_ttl",
        type=int,
        default=30,
        metavar="max_ttl",
        help="Set the max number of max_ttl (max TTL to be reached). \
              Default is 30",
    )
    optional.add_argument(
        "-n",
        dest="dont_resolve",
        action="store_true",
        default=False,
        help="Do not resolve IP addresses to their domain names",
    )
    optional.add_argument(
        "--no-inc-port",
        dest="no_inc_port",
        action="store_true",
        default=False,
        help="Don't increment destination port per hop, Default is False",
    )
    optional.add_argument(
        "-p",
        "--port",
        dest="port",
        type=int,
        default=33434,
        metavar="port",
        help="Set the destination port to use (UDP only), Default is 33434",
    )
    optional.add_argument(
        "-q",
        "--queries",
        dest="nqueries",
        type=int,
        default=3,
        metavar="nqueries",
        help="Set the number of probes per each hop. Default is 3",
    )
    optional.add_argument(
        "--quiet",
        dest="quiet",
        action="store_true",
        default=False,
        help="Do not print anything",
    )
    optional.add_argument(
        "-s",
        "--source",
        dest="src_addr",
        default="0.0.0.0",
        metavar="src_addr",
        help="Use source src_addr for outgoing packets",
    )
    optional.add_argument(
        "--sport",
        dest="sport",
        type=int,
        default=0,
        metavar="sport",
        help="Use source port num for outgoing packets (UDP only), \
              Default is 0 (OS decides)",
    )
    optional.add_argument(
        "--udp-format",
        dest="udp_format",
        default="rtp",
        metavar="udp_format",
        help="UDP payload format, 'rtp' or 'dns', anything else is plain UDP",
    )
    optional.add_argument(
        "-w",
        "--wait",
        dest="max_wait",
        type=float,
        default=1.0,
        metavar="max_wait",
        help="Wait for a probe no more than this amount of seconds. \
              Default is 1.0 (float)",
    )
    optional_dns.add_argument(
        "--dns-query",
        dest="dns_query",
        default="google.com",
        metavar="domain",
        help="DNS query target, Default is 'google.com', \
              used in conjunction with 'udp_format=dns'",
    )
    optional_rtp.add_argument(
        "--no-inc-seq",
        dest="no_inc_seq",
        action="store_true",
        default=False,
        help="Don't increment RTP sequence number per hop, Default is False",
    )
    optional_rtp.add_argument(
        "--no-inc-timestamp",
        dest="no_inc_timestamp",
        action="store_true",
        default=False,
        help="Don't increment RTP timestamp per hop by 160, Default is False",
    )
    optional_rtp.add_argument(
        "--payload-type",
        dest="payload_type",
        type=int,
        default=0,
        metavar="payload_type",
        help="RTP payload type, Default is 0 (G711u)",
    )
    optional_rtp.add_argument(
        "--seq",
        dest="seq",
        type=int,
        default=0,
        metavar="seq",
        help="RTP sequence number, Default is 0",
    )
    optional_rtp.add_argument(
        "--ssrc",
        dest="ssrc",
        type=int,
        default=3735928559,
        metavar="ssrc",
        help="RTP SSRC number, Default is 3735928559 (0xdeadbeef)",
    )
    optional_rtp.add_argument(
        "--timestamp",
        dest="timestamp",
        type=int,
        default=0,
        metavar="timestamp",
        help="RTP timestamp, Default is 0",
    )
    positional.add_argument("host", help="The host to traceroute to")
    positional.add_argument(
        "packetlen",
        nargs="?",
        type=int,
        default=214,
        help=f"UDP payload length (default is 214, 44 + 172)",
    )
    args = parser.parse_args()
    try:
        rv: int = traceroute(
            host=args.host,
            port=args.port,
            max_ttl=args.max_ttl,
            dont_resolve=args.dont_resolve,
            first_ttl=args.first_ttl,
            device=args.device,
            src_addr=args.src_addr,
            sport=args.sport,
            nqueries=args.nqueries,
            icmp=args.icmp,
            max_wait=args.max_wait,
            packetlen=args.packetlen,
            udp_format=args.udp_format,
            dns_query=args.dns_query,
            seq=args.seq,
            timestamp=args.timestamp,
            ssrc=args.ssrc,
            payload_type=args.payload_type,
            no_inc_seq=args.no_inc_seq,
            no_inc_port=args.no_inc_port,
            no_inc_timestamp=args.no_inc_timestamp,
            quiet=args.quiet,
        )
        sys.exit(rv)
    except KeyboardInterrupt:
        print("Application terminated by user")
        sys.exit(2)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(3)
