# ciphers_frm_pcap
Extract client side cipher suites and list of interacted servers from a pcap file.

Usage:
First create a pcap file to analyse.
Install wireshark/tshark for the purpose.

Create pcap file:
  tshark -i en0 -w capture.pcap

python3 ciphers_frm_pcap.py capture.pcap
