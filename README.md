# traceroute
Implements basic UDP and ICMP traceroute using python3.

```
UDP/ICMP traceroute

optional arguments:
  -h, --help            show this help message and exit
  -f first_ttl, --first=first_ttl
                        Start from the first_ttl max_ttl (instead from 1)
  -I, --icmp            Use ICMP ECHO for tracerouting
  -i device, --interface=device
                        Specify a network interface to operate with
  -m max_ttl, --max-hops=max_ttl
                        Set the max number of max_ttl (max TTL to bereached).
                        Default 30
  -n                    Do not resolve IP hostesses to their domain names
  -p port, --port=port  Set the destination port to use, Default 33434
  -w max_wait, --wait=max_wait
                        Wait for a probe no more than this seconds. Default
                        1.0
  -q nqueries, --queries=nqueries
                        Set the number of probes per each max_ttl. Default 3
  -s src_addr, --source=src_addr
                        Use source src_addr for outgoing packets
  --sport=              Use source port num for outgoing packets, Default 0

positional arguments:
  host                  The host to traceroute to
  packetlen             The full packet length (default is the length of an IP
                        header plus 40)
```