# traceroute
UDP/ICMP traceroute with optional RTP/DNS payload in UDP.

```
optional arguments:
  -h, --help            show this help message and exit
  --dns-query=dns_query
                        DNS query target, Default is 'google.com', used in
                        conjunction with 'udp_format=dns'
  -f first_ttl, --first=first_ttl
                        Start from the first_ttl (instead from 1)
  -I, --icmp            Use ICMP ECHO for tracerouting
  -i device, --interface=device
                        Specify a network interface to operate with
  --inc-seq             Increment RTP sequence number per ttl
  -m max_ttl, --max-hops=max_ttl
                        Set the max number of max_ttl (max TTL to be reached).
                        Default is 30
  -n                    Do not resolve IP addresses to their domain names
  -p port, --port=port  Set the destination port to use, Default is 33434
  --payload-type=payload_type
                        RTP payload type, Default is 0 (G711u)
  --udp-format=udp_format
                        UDP payload format, 'rtp' or 'dns', anything else is
                        plain UDP
  -w max_wait, --wait=max_wait
                        Wait for a probe no more than this amount of seconds.
                        Default is 1.0 (float)
  -q nqueries, --queries=nqueries
                        Set the number of probes per each hop. Default is 3
  --quiet               Do not print anything
  --seq=seq             RTP sequence number, Default is 0
  -s src_addr, --source=src_addr
                        Use source src_addr for outgoing packets
  --sport=sport         Use source port num for outgoing packets, Default is 0
                        (OS decides)
  --ssrc=ssrc           RTP SSRC number, Default is 3735928559 (0xdeadbeef)
  --timestamp=timestamp
                        RTP timestamp, Default is 0

positional arguments:
  host                  The host to traceroute to
  packetlen             UDP payload length (default is 172, 44 + 172 = 214
                        total)
```