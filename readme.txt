# how to execute pcap
./pcap [the number of captured packet] [device name]

# why don't use pcap_lookupdev?
in my virtual circumstance, when i used pcap_lookupdev,
pcap only catched "bluetooth0" device.

# what is my captured packet?
only IP packet in L3.
and if it is TCP in L4, it will print TCP header.
