# ciphers_frm_pcap

Identifies client-side weak cipher suites and lists interacted servers from a PCAP file.

## Overview

This script analyzes a packet capture (PCAP) file to identify the TLS/SSL cipher suites offered by clients during handshakes. Its primary goal is to help identify potentially **weak or outdated cipher suites** proposed by clients. Additionally, it extracts a list of the unique server names the clients interacted with. The analysis results are conveniently organized into an Excel file.

## Prerequisites

Before using this script, ensure you have the following installed:

* **Python 3:** The script is written in Python 3. You can download it from [https://www.python.org/downloads/](https://www.python.org/downloads/).
* **tshark (Wireshark command-line utility):** This tool is used to capture network traffic and is typically installed with Wireshark. You can download Wireshark from [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html).

## Usage

### 1. Create a PCAP file

You can capture network traffic and save it to a PCAP file using `tshark`. For example, to capture traffic on the `en0` interface and save it to `capture.pcap`, run the following command in your terminal:

```bash
tshark -i en0 -w capture.pcap

```

### 2. Extract the cipher suites

Run the following command in your terminal:

```bash
python3 ciphers_frm_pcap.py capture.pcap

