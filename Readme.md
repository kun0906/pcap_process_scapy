# Purpose

  - Achieve Streams information by scapy.
  - TCP and UDP streams in this source are based on five tuple <srcIP:srcPort<->dstIP:dstPort-protocol>, ignore the direction.
  - srcIP->dstIP and dstIP->srcIP are different flow, but they belongs to the same stream (bi-directional flows).
  - all packets with the same 5-touple (source host, destination host, source port, destination port, transport protocol)
  - regardless of packet direction are considered part of the same session [1].

## Note
    1) the stream's calculation is not based on TCP 3 handshake, only on five tuple, so there will be problems if multiple TCP streams have the same tuple.
       (If there will exist multiple TCP streams have the same five tuple?)
       In new wireshark version, there will be more complicated to calculate stream.
    2) it does not perform any proper TCP session reassembly. and out-of-order TCP packets will also cause the data to be store in an out of sequence.
    3) ICMP do not have port, so it can not be recognized as stream.
## References
    [1]: https://stackoverflow.com/questions/6076897/follow-tcp-stream-where-does-field-stream-index-come-from
    2. https://osqa-ask.wireshark.org/questions/59467/tcp-stream-index-question
    3. https://blog.packet-foo.com/2015/03/tcp-analysis-and-the-five-tuple/
    4. https://www.netresec.com/?page=SplitCap
    5. https://stackoverflow.com/questions/32317848/multiple-tcp-connection-on-same-ip-and-port/32318220