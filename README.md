# traceroute
UDP/ICMP traceroute with optional DNS/RTP payload in UDP.

Usage:

```
python3 traceroute.py -q 1 -w 0.2 -m 20 --sport=2048 -p 2050 -i B1 192.160.10.8
```

```
optional arguments:
  -h, --help            show this help message and exit
  -f first_ttl, --first=first_ttl
                        Start from the first_ttl (not from 1)
  -i device, --interface=device
                        Specify a network interface to operate with
  -I, --icmp            Use ICMP ECHO for tracerouting
  -m max_ttl, --max-hops=max_ttl
                        Set the max number of max_ttl (max TTL to be reached).
                        Default is 30
  -n                    Do not resolve IP addresses to their domain names
  --no-inc-port         Don't increment destination port per hop, Default is
                        False
  -p port, --port=port  Set the destination port to use (UDP only), Default is
                        33434
  -q nqueries, --queries=nqueries
                        Set the number of probes per each hop. Default is 3
  --quiet               Do not print anything
  -s src_addr, --source=src_addr
                        Use source src_addr for outgoing packets
  --sport=sport         Use source port num for outgoing packets (UDP only),
                        Default is 0 (OS decides)
  --udp-format=udp_format
                        UDP payload format, 'rtp' or 'dns', anything else is
                        plain UDP
  -w max_wait, --wait=max_wait
                        Wait for a probe no more than this amount of seconds.
                        Default is 1.0 (float)

optional UDP/DNS arguments:
  --dns-query=domain    DNS query target, Default is 'google.com', used in
                        conjunction with 'udp_format=dns'

optional UDP/RTP arguments:
  --no-inc-seq          Don't increment RTP sequence number per hop, Default
                        is False
  --no-inc-timestamp    Don't increment RTP timestamp per hop by 160, Default
                        is False
  --payload-type=payload_type
                        RTP payload type, Default is 0 (G711u)
  --seq=seq             RTP sequence number, Default is 0
  --ssrc=ssrc           RTP SSRC number, Default is 3735928559 (0xdeadbeef)
  --timestamp=timestamp
                        RTP timestamp, Default is 0

positional arguments:
  host                  The host to traceroute to
  packetlen             UDP payload length (default is 214, 44 + 172)
```