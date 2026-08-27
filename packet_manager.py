"""TUN plumbing, framed records, and central peer routing."""

import ipaddress
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

from encryptDecrypt import SessionCipher
from protocol import MAX_FRAME_SIZE, send_frame
from tun import close_tun, create_tun, set_if_up


def recv_frames_from_socket(sock: socket.socket, stop_event: threading.Event):
    """Yield complete length-prefixed records from a TCP stream."""
    buffer = bytearray()
    old_timeout = sock.gettimeout()
    sock.settimeout(1.0)
    try:
        while not stop_event.is_set():
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)
                while len(buffer) >= 4:
                    length = struct.unpack("!I", buffer[:4])[0]
                    if length > MAX_FRAME_SIZE:
                        raise ValueError("frame is too large")
                    if len(buffer) < 4 + length:
                        break
                    frame = bytes(buffer[4 : 4 + length])
                    del buffer[: 4 + length]
                    yield frame
            except socket.timeout:
                continue
    finally:
        sock.settimeout(old_timeout)


def parse_ip_packet(packet: bytes):
    try:
        if not packet:
            return "Empty packet"
        version = packet[0] >> 4
        if version == 6:
            if len(packet) < 40:
                return "Incomplete IPv6 packet"
            source = ipaddress.IPv6Address(packet[8:24])
            destination = ipaddress.IPv6Address(packet[24:40])
            return f"IPv6: {source} -> {destination} (next-header: {packet[6]})"
        if len(packet) < 20 or version != 4:
            return "Unknown or incomplete IP packet"
        ihl = (packet[0] & 0xF) * 4
        if ihl < 20 or len(packet) < ihl:
            return "Invalid IPv4 packet"
        protocol = packet[9]
        src_ip = str(ipaddress.IPv4Address(packet[12:16]))
        dst_ip = str(ipaddress.IPv4Address(packet[16:20]))
        return f"IPv4: {src_ip} -> {dst_ip} (proto: {protocol})"
    except Exception:
        return "Unable to parse packet"


def packet_endpoints(packet: bytes) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        raise ValueError("only complete IPv4 packets are supported")
    ihl = (packet[0] & 0xF) * 4
    if ihl < 20 or len(packet) < ihl:
        raise ValueError("invalid IPv4 header")
    return ipaddress.IPv4Address(packet[12:16]), ipaddress.IPv4Address(packet[16:20])


class PeerConnection:
    def __init__(self, sock: socket.socket, address, vpn_ip: str, session):
        self.sock = sock
        self.address = address
        self.vpn_ip = ipaddress.IPv4Address(vpn_ip)
        self.device_tag = session.device_tag
        self.device_public_key = session.device_public_key
        self.session = session
        self.send_lock = threading.Lock()
        self.stop_event = threading.Event()

    def send_packet(self, packet: bytes):
        # Encryption and framing must share one lock: otherwise two server
        # threads could allocate record sequence N/N+1 and write them reversed.
        with self.send_lock:
            encrypted = self.session.send_cipher.encrypt(packet)
            send_frame(self.sock, encrypted)

    def close(self):
        self.stop_event.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class PeerRegistry:
    """Thread-safe mapping between assigned VPN addresses and peer sockets."""

    def __init__(self, network: str = "10.0.0.0/24", server_ip: str = "10.0.0.1"):
        self.network = ipaddress.ip_network(network, strict=False)
        if self.network.version != 4:
            raise ValueError("the current TUN router supports an IPv4 VPN network")
        self.server_ip = ipaddress.ip_address(server_ip)
        if self.server_ip not in self.network:
            raise ValueError("server IP must be inside the VPN network")
        self._peers: dict[ipaddress.IPv4Address, PeerConnection] = {}
        self._tags: dict[str, PeerConnection] = {}
        self._reserved: set[ipaddress.IPv4Address] = set()
        self._lock = threading.RLock()

    def reserve_ip(self) -> str:
        with self._lock:
            for candidate in self.network.hosts():
                if candidate == self.server_ip:
                    continue
                if candidate not in self._peers and candidate not in self._reserved:
                    self._reserved.add(candidate)
                    return str(candidate)
        raise RuntimeError("VPN address pool is exhausted")

    def release_ip(self, vpn_ip: str):
        with self._lock:
            self._reserved.discard(ipaddress.ip_address(vpn_ip))

    def register(self, peer: PeerConnection):
        previous = None
        with self._lock:
            if peer.vpn_ip not in self._reserved:
                raise ValueError("peer IP was not reserved")
            self._reserved.remove(peer.vpn_ip)
            self._peers[peer.vpn_ip] = peer
            if peer.device_tag:
                previous = self._tags.get(peer.device_tag)
                self._tags[peer.device_tag] = peer
        if previous is not None and previous is not peer:
            previous.close()

    def remove(self, peer: PeerConnection):
        with self._lock:
            if self._peers.get(peer.vpn_ip) is peer:
                del self._peers[peer.vpn_ip]
            if peer.device_tag and self._tags.get(peer.device_tag) is peer:
                del self._tags[peer.device_tag]

    def get(self, vpn_ip: str | ipaddress.IPv4Address) -> PeerConnection | None:
        with self._lock:
            return self._peers.get(ipaddress.ip_address(vpn_ip))

    def get_by_tag(self, device_tag: str) -> PeerConnection | None:
        with self._lock:
            return self._tags.get(device_tag)

    def snapshot(self) -> list[PeerConnection]:
        with self._lock:
            return list(self._peers.values())


def setup_client_routing(ifname: str, server_endpoint: str, tun_ip: str):
    try:
        out = subprocess.check_output(["ip", "route", "get", server_endpoint]).decode().strip()
        parts = out.split()
        gw = parts[parts.index("via") + 1] if "via" in parts else None
        dev = parts[parts.index("dev") + 1] if "dev" in parts else None
        vpn_source = tun_ip.split("/", 1)[0]
        original = {"gw": gw, "dev": dev, "server": server_endpoint, "ifname": ifname}

        if gw and dev:
            subprocess.run(
                ["ip", "route", "add", f"{server_endpoint}/32", "via", gw, "dev", dev],
                check=False,
            )
        elif dev:
            subprocess.run(["ip", "route", "add", f"{server_endpoint}/32", "dev", dev], check=False)

        subprocess.run(
            ["ip", "route", "add", "0.0.0.0/1", "dev", ifname, "src", vpn_source],
            check=False,
        )
        subprocess.run(
            ["ip", "route", "add", "128.0.0.0/1", "dev", ifname, "src", vpn_source],
            check=False,
        )
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", ifname, "-j", "MASQUERADE"],
            check=False,
        )
        subprocess.run(["conntrack", "-F"], check=False)
        print(f"[DEBUG] Full-tunnel routing via {ifname}")
        return original
    except Exception as exc:
        print(f"Error setting up routes: {exc}")
        return None


def restore_client_routing(original_route):
    if not original_route:
        return
    try:
        server_ip = original_route.get("server")
        ifname = original_route.get("ifname", "tun0")
        if server_ip:
            subprocess.run(["ip", "route", "del", f"{server_ip}/32"], check=False)
        subprocess.run(["ip", "route", "del", "0.0.0.0/1", "dev", ifname], check=False)
        subprocess.run(["ip", "route", "del", "128.0.0.0/1", "dev", ifname], check=False)
        subprocess.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", ifname, "-j", "MASQUERADE"], check=False)
    except Exception as exc:
        print(f"Error restoring routes: {exc}")


def start_client_packet_manager(sock: socket.socket, session, tun_name, tun_ip, debug_level=0, on_ready=None):
    stop_event = threading.Event()
    original_route = None
    tun = None
    try:
        tun, ifname = create_tun(tun_name)
        set_if_up(ifname, tun_ip)
        original_route = setup_client_routing(ifname, sock.getpeername()[0], tun_ip)

        vpn_ip_str = tun_ip.split("/")[0]

        def tun_to_net():
            count = 0
            try:
                while not stop_event.is_set():
                    packet = tun.read(2000)
                    if not packet:
                        continue
                    try:
                        source, dest = packet_endpoints(packet)
                        if str(source) != vpn_ip_str:
                            if debug_level:
                                print(f"[CLIENT DROP] spoofed source {source} -> {dest}")
                            continue
                    except ValueError:
                        pass
                    if debug_level:
                        print(f"[CLIENT->SERVER] #{count}: {parse_ip_packet(packet)}")
                    send_frame(sock, session.send_cipher.encrypt(packet))
                    count += 1
            except Exception as exc:
                if not stop_event.is_set():
                    print("tun_to_net exiting:", exc)
                stop_event.set()

        def net_to_tun():
            count = 0
            try:
                for frame in recv_frames_from_socket(sock, stop_event):
                    packet = session.receive_cipher.decrypt(frame)
                    if debug_level:
                        print(f"[SERVER->CLIENT] #{count}: {parse_ip_packet(packet)}")
                    tun.write(packet)
                    count += 1
            except Exception as exc:
                if not stop_event.is_set():
                    print("net_to_tun exiting:", exc)
                stop_event.set()

        t1 = threading.Thread(target=tun_to_net, daemon=True, name="client-tun-to-net")
        t2 = threading.Thread(target=net_to_tun, daemon=True, name="client-net-to-tun")
        t1.start()
        t2.start()
        print(f"[client] TUN {ifname} up as {tun_ip}; forwarding started")
        if debug_level:
            print(f"[client] key exchange={session.key_exchange}, cipher={session.cipher}")

        def handle_sigint(signum, frame):
            stop_event.set()
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            close_tun(tun)
            sys.exit(0)

        try:
            signal.signal(signal.SIGINT, handle_sigint)
        except ValueError:
            pass
            
        if on_ready:
            on_ready()
            
        while t1.is_alive() and t2.is_alive():
            time.sleep(0.5)
    finally:
        stop_event.set()
        try:
            sock.close()
        except OSError:
            pass
        # Remove routes while the interface still exists; closing a TUN file
        # descriptor can make the kernel remove the device first.
        restore_client_routing(original_route)
        if tun is not None:
            close_tun(tun)


def start_peer_packet_manager(
    peer: PeerConnection,
    tun,
    registry: PeerRegistry,
    tun_write_lock: threading.Lock,
    debug_level=0,
):
    """Read one peer's records and route each decrypted IP packet."""
    try:
        for frame in recv_frames_from_socket(peer.sock, peer.stop_event):
            packet = peer.session.receive_cipher.decrypt(frame)
            try:
                source, destination = packet_endpoints(packet)
            except ValueError as exc:
                # This build assigns IPv4 addresses and routes IPv4.  IPv6
                # and other TUN frames are valid encrypted records, but are
                # not routable by this registry; do not disconnect the peer.
                if debug_level:
                    print(f"[server] dropped unsupported peer packet: {exc}")
                continue
            if source != peer.vpn_ip:
                print(f"[server] dropped spoofed source {source} from {peer.vpn_ip}")
                continue
            if debug_level:
                print(f"[PEER {peer.vpn_ip}] {parse_ip_packet(packet)}")

            destination_peer = registry.get(destination)
            if destination_peer is not None:
                destination_peer.send_packet(packet)
            elif destination in registry.network:
                # An address in the VPN subnet with no registered peer is not
                # an Internet destination and must not leak to NAT.
                if debug_level:
                    print(f"[server] no peer registered for {destination}")
            else:
                # Preserve the original VPN architecture: non-VPN traffic is
                # injected into the server TUN and handled by the host/NAT.
                with tun_write_lock:
                    tun.write(packet)
    except Exception as exc:
        if not peer.stop_event.is_set():
            print(f"[server] peer {peer.vpn_ip} disconnected: {exc}")
    finally:
        peer.stop_event.set()
        registry.remove(peer)
        peer.close()


def start_server_tun_router(
    tun,
    registry: PeerRegistry,
    stop_event: threading.Event,
    debug_level=0,
):
    """Route packets arriving from the Internet-facing server TUN to peers."""
    try:
        while not stop_event.is_set():
            packet = tun.read(65535)
            if not packet:
                continue
            try:
                _, destination = packet_endpoints(packet)
            except ValueError as exc:
                if debug_level:
                    print(f"[server] dropped unsupported TUN packet: {exc}")
                continue
            destination_peer = registry.get(destination)
            if destination_peer is not None:
                if debug_level:
                    print(f"[TUN->PEER {destination_peer.vpn_ip}] {parse_ip_packet(packet)}")
                destination_peer.send_packet(packet)
            elif debug_level and destination in registry.network:
                print(f"[server] TUN packet has no registered destination: {destination}")
    except Exception as exc:
        if not stop_event.is_set():
            print("server TUN router exiting:", exc)


def _default_route_interface() -> str:
    output = subprocess.check_output(["ip", "route", "show", "default"], text=True)
    for line in output.splitlines():
        fields = line.split()
        if "dev" in fields:
            return fields[fields.index("dev") + 1]
    raise RuntimeError("could not determine the default-route network interface")


def setup_server_nat(nat_interface: str | None = None):
    if not nat_interface:
        nat_interface = _default_route_interface()
    try:
        socket.if_nametoindex(nat_interface)
    except OSError as exc:
        raise ValueError(
            f"NAT interface {nat_interface!r} does not exist; "
            "pass the EC2 interface with --nat-interface"
        ) from exc
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
    subprocess.run(
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", nat_interface, "-j", "MASQUERADE"],
        check=False,
    )
    subprocess.run(["iptables", "-A", "FORWARD", "-i", "tun+", "-j", "ACCEPT"], check=False)
    subprocess.run(["iptables", "-A", "FORWARD", "-o", "tun+", "-j", "ACCEPT"], check=False)
    print(f"[DEBUG] NAT configured on {nat_interface}")
