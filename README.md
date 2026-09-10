# ARP Spoofer

A Linux-based educational tool for understanding **ARP cache poisoning, MITM traffic forwarding, packet sniffing, and traffic blocking** using Python and Scapy.

The project was built as a hands-on way to understand how ARP poisoning works at the packet level rather than only studying the theory.

> ⚠️ **For educational and authorized testing only.**
> Run this tool only on networks and devices you own or have explicit permission to test. Unauthorized interception or disruption of network traffic may be illegal.

## Features

* 🔎 **LAN discovery**

  * Scans the local IPv4 subnet using ARP requests.
  * Resolves discovered hosts to their MAC addresses.

* 🕸️ **ARP cache poisoning**

  * Sends forged ARP replies to selected hosts.
  * Makes targets associate the attacker's MAC address with the gateway.
  * Also poisons the gateway's ARP cache for the selected targets.

* 🔀 **IP forwarding**

  * Enables Linux IPv4 forwarding so intercepted traffic can continue through the machine.

* 👀 **Packet inspection**

  * Displays traffic involving selected targets.
  * Shows protocol, source/destination IPs, and ports.
  * Extracts DNS queries when visible.
  * Can identify basic HTTP requests and `Host` headers.
  * Encrypted protocols such as HTTPS and DoT do not expose their application data.

* 🚫 **Traffic blocking**

  * Uses `iptables` to selectively drop forwarded traffic.
  * Targets can be blocked or allowed while the program is running.

* 🧹 **Automatic cleanup**

  * Restores the original ARP mappings when the program exits.
  * Removes temporary firewall rules.
  * Restores the previous `ip_forward` state.

## How It Works

The tool combines several Linux networking mechanisms:

```text
             ┌──────────────┐
             │   Gateway    │
             │  10.0.0.1    │
             └──────┬───────┘
                    │
              ARP poisoning
                    │
             ┌──────▼───────┐
             │   This host  │
             │  MITM node   │
             └──────┬───────┘
                    │
              ARP poisoning
                    │
             ┌──────▼───────┐
             │    Target    │
             │  10.0.0.x    │
             └──────────────┘
```

### 1. Host Discovery

At startup, the program sends ARP requests across the selected subnet and builds a mapping of:

```text
IP address → MAC address
```

The local machine and gateway are excluded from the normal target list.

### 2. ARP Poisoning

The program periodically sends forged ARP replies:

```text
Target → "The gateway is at my MAC address"

Gateway → "The target is at my MAC address"
```

This causes traffic between the target and gateway to pass through the machine running the tool.

### 3. IP Forwarding

Linux forwarding is enabled so intercepted packets can continue toward their destination.

The original forwarding state is saved and restored when the program exits.

### 4. Packet Sniffing

Scapy captures packets involving the selected targets.

For plaintext protocols, additional information can sometimes be extracted:

```text
[DNS]   10.0.0.8 -> 10.0.0.1  query: example.com
[TCP]   10.0.0.8 -> 93.x.x.x  port 49152->80
```

Encrypted protocols such as HTTPS do not expose their application-layer contents to the sniffer.

### 5. Traffic Blocking

Blocking is implemented separately from ARP poisoning using `iptables`:

```text
Target
   │
   ▼
This host
   │
   ├── allowed  → forwarded normally
   │
   └── blocked  → dropped by FORWARD rules
```

The ARP state remains poisoned while traffic is blocked, so the target continues attempting to communicate through the machine.

### 6. Cleanup

When the program receives `Ctrl+C` or `quit`, it:

1. Stops packet processing.
2. Removes temporary `iptables` rules.
3. Sends corrective ARP replies.
4. Restores the original `ip_forward` value.
5. Exits cleanly.

## Requirements

* Linux
* Python 3
* Root privileges
* Scapy
* iptables
* An IPv4 LAN where the machine can send/receive ARP frames

### Arch Linux

```bash
sudo pacman -S python-scapy iptables
```

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/arp-spoofer.git
cd arp-spoofer
```

No additional build step is required.

## Usage

### Spoof the discovered LAN targets

```bash
sudo python3 arp_spoofer.py enp1s0 10.0.0.1
```

### Specify targets manually

```bash
sudo python3 arp_spoofer.py enp1s0 10.0.0.1 \
  --targets 10.0.0.8,10.0.0.9
```

### Start with a target blocked

```bash
sudo python3 arp_spoofer.py enp1s0 10.0.0.1 \
  --block 10.0.0.8
```

Block every discovered target:

```bash
sudo python3 arp_spoofer.py enp1s0 10.0.0.1 \
  --block all
```

### Disable packet sniffing

```bash
sudo python3 arp_spoofer.py enp1s0 10.0.0.1 \
  --no-sniff
```

## Interactive Commands

While the program is running:

| Command      | Description                                    |
| ------------ | ---------------------------------------------- |
| `list`       | Show discovered targets and their status       |
| `block <ip>` | Block a specific target                        |
| `block all`  | Block all discovered targets                   |
| `allow <ip>` | Allow a specific target again                  |
| `allow all`  | Allow all targets                              |
| `quit`       | Stop the program and restore the network state |

## Finding Your Interface and Gateway

List network interfaces:

```bash
ip a
```

Find the default gateway:

```bash
ip route | grep default
```

Optional ARP-based host discovery:

```bash
sudo arp-scan --interface=<interface> --localnet
```

## Limitations

* **IPv4 only** — IPv6/NDP is not currently supported.
* **Single discovery pass** — hosts joining the network after startup are not automatically discovered.
* **Encrypted traffic** — HTTPS, DoT, and other encrypted protocols do not expose their application-layer contents.
* **Flat subnet assumption** — the tool is designed for a single local broadcast domain and does not cross routers or VLAN boundaries.
* **Linux-specific** — the implementation relies on Linux `ip_forward`, raw packet access, and `iptables`.
* **Network-dependent** — behavior can vary depending on switches, ARP inspection, client isolation, firewall rules, and other network protections.

## Project Structure

```text
arp-spoofer/
├── arp_spoofer.py
├── README.md
└── images/
    └── ...
```

## Learning Goals

This project was created to gain practical experience with:

* ARP and Ethernet frames
* ARP cache poisoning
* Man-in-the-middle concepts
* Linux IP forwarding
* Linux firewalling with iptables
* Packet capture and protocol inspection
* Scapy
* Network discovery
* Multithreading and synchronization in Python
* Safe cleanup and state restoration

## Responsible Use

This project is intended for:

* Personal networks
* Isolated security labs
* CTFs and educational environments
* Systems where you have explicit authorization to test

**Do not use it to intercept, disrupt, or monitor traffic on networks or devices without permission.**

## License

Use responsibly and only in environments where you have permission to perform network security testing.

