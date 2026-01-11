#!/usr/local/ipcs/peon/venv/bin/python3
# -*- encoding: utf-8 -*-
##############################################################################
## Name: traceroute.py
## Purpose: Implements basic UDP and ICMP traceroute using python3
## Date: 2026-01-10
## Author: sszokoly@protonmail.com
## License: MIT
## Version: 0.1
## Source: https://github.com/sszokoly/traceroute
##############################################################################

import os
import time
import select
import socket
import struct
import fcntl
import array
import platform
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
    if device is None:
        devices = [x for x in get_interface_names() if x != "lo"]
        if not devices:
            raise OSError("No network devices found (excluding loopback)")
        else:
            device = devices[0]
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


def get_route(
    host: str,
    max_ttl: int = 30,
    port: int = 33433,
    dont_resolve: bool = False,
    first_ttl: int = 1,
    device=None,
    src_addr: str = "0.0.0.0",
    sport: int = 0,
    nqueries: int = 3,
    icmp: bool = False,
    max_wait: float = 1.0,
    packetlen: int = 40,
) -> int:
    if not is_ip_address(host):
        resolved_host = socket.gethostbyname(host)
    else:
        resolved_host = host

    print(
        "traceroute to {} ({}), {} hops max, {} byte packets".format(
            host, resolved_host, max_ttl, packetlen
        )
    )

    for ttl in range(first_ttl, max_ttl + 1):
        cur = None
        result = HopResult(nqueries=nqueries)
        print(f" {ttl} ", end="")

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
                    send_socket.sendto(packet, (resolved_host, 0))
                else:
                    # Send UDP packet
                    payload = "A" * packetlen
                    send_socket.sendto(payload.encode(), (resolved_host, port))
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

        print_result(result, dont_resolve)

        if cur == resolved_host:
            return 0

        if ttl == max_ttl:
            break

    return 1


if __name__ == "__main__":
    import argparse
    import sys

    # sys.argv.extend(['8.8.8.8'])

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
        description="UDP/ICMP traceroute",
        add_help=False,
        formatter_class=CustomHelpFormatter,
    )

    # Create custom groups in desired order
    optional = parser.add_argument_group("optional arguments")
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
        help="Start from the first_ttl max_ttl (instead from 1)",
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
        "-i",
        "--interface",
        dest="device",
        default=None,
        metavar="device",
        help="Specify a network interface to operate with",
    )
    optional.add_argument(
        "-m",
        "--max-hops",
        dest="max_ttl",
        type=int,
        default=30,
        metavar="max_ttl",
        help="Set the max number of max_ttl (max TTL to bereached). Default 30",
    )
    optional.add_argument(
        "-n",
        dest="dont_resolve",
        action="store_true",
        default=False,
        help="Do not resolve IP hostesses to their domain names",
    )
    optional.add_argument(
        "-p",
        "--port",
        dest="port",
        type=int,
        default=33434,
        metavar="port",
        help="Set the destination port to use, Default 33434",
    )
    optional.add_argument(
        "-w",
        "--wait",
        dest="max_wait",
        type=float,
        default=1,
        metavar="max_wait",
        help="Wait for a probe no more than this seconds. Default 1.0",
    )
    optional.add_argument(
        "-q",
        "--queries",
        dest="nqueries",
        type=int,
        default=3,
        metavar="nqueries",
        help="Set the number of probes per each max_ttl. Default 3",
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
        metavar="",
        help="Use source port num for outgoing packets, Default 0",
    )
    positional.add_argument("host", help="The host to traceroute to")
    positional.add_argument(
        "packetlen",
        nargs="?",
        type=int,
        default=40,
        help=f"The full packet length (default is the length of an IP \
               header plus 40)",
    )
    args = parser.parse_args()
    try:
        rv: int = get_route(
            args.host,
            args.max_ttl,
            args.port,
            dont_resolve=args.dont_resolve,
            first_ttl=args.first_ttl,
            device=args.device,
            src_addr=args.src_addr,
            sport=args.sport,
            nqueries=args.nqueries,
            icmp=args.icmp,
            max_wait=args.max_wait,
            packetlen=args.packetlen,
        )
        sys.exit(rv)
    except KeyboardInterrupt:
        print("Application terminated by user")
        sys.exit(2)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(3)
