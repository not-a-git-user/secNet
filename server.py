from dotenv import load_dotenv
load_dotenv()
import socket
import threading
import os
import time
import hashlib

from chat.chat_service import ChatService, run_chat_service
from encryptDecrypt import SUPPORTED_CIPHERS
from handshake import available_key_exchanges, server_handshake
from chat.kafka_backend import KafkaBus, KafkaDeviceDirectory
from packet_manager import (
    PeerConnection,
    PeerRegistry,
    close_tun,
    create_tun,
    set_if_up,
    setup_server_nat,
    start_peer_packet_manager,
    start_server_tun_router,
)


def _serve_peer(
    conn,
    address,
    registry: PeerRegistry,
    tun,
    tun_write_lock: threading.Lock,
    stop_event: threading.Event,
    key_exchange: str,
    cipher: str,
    device_directory: KafkaDeviceDirectory,
    kafka_bus: KafkaBus,
    debug_level: int,
):
    reserved_ip = None
    peer = None
    try:
        reserved_ip = registry.reserve_ip()
        session = server_handshake(
            conn,
            reserved_ip,
            key_exchange,
            cipher,
            device_directory=device_directory,
        )
        peer = PeerConnection(conn, address, reserved_ip, session)
        registry.register(peer)
        kafka_bus.publish(
            "network-events",
            session.device_tag,
            {
                "event": "session_authenticated",
                "device_tag": session.device_tag,
                "device_id": hashlib.sha256(session.device_public_key).hexdigest(),
                "vpn_ip": reserved_ip,
                "remote": str(address),
                "created_at": time.time(),
            },
        )
        kafka_bus.publish(
            "network-events",
            session.device_tag,
            {
                "event": "peer_join",
                "device_tag": session.device_tag,
                "vpn_ip": reserved_ip,
                "remote": str(address),
                "key_exchange": session.key_exchange,
                "cipher": session.cipher,
                "created_at": time.time(),
            },
        )
        kafka_bus.publish(
            "network-events",
            session.device_tag,
            {
                "event": "ip_changed",
                "device_tag": session.device_tag,
                "vpn_ip": reserved_ip,
                "created_at": time.time(),
            },
        )
        print(
            f"[server] peer {address} registered as {reserved_ip}; "
            f"key exchange={session.key_exchange}, cipher={session.cipher}"
        )
        start_peer_packet_manager(peer, tun, registry, tun_write_lock, debug_level)
    except Exception as exc:
        print(f"[server] handshake/peer setup failed for {address}: {exc}")
        if peer is not None:
            registry.remove(peer)
            peer.close()
        elif reserved_ip is not None:
            registry.release_ip(reserved_ip)
        try:
            conn.close()
        except OSError:
            pass
    finally:
        # A reconnect with the same persistent identity replaces the old
        # socket in PeerRegistry.  Do not emit a leave event for that old
        # socket after the replacement has already become active.
        if (
            peer is not None
            and peer.device_tag
            # The packet manager removes a normally disconnected peer before
            # returning.  A replacement session leaves a different peer at
            # this tag, so only the empty case is a real leave.
            and registry.get_by_tag(peer.device_tag) is None
        ):
            try:
                kafka_bus.publish(
                    "network-events",
                    peer.device_tag,
                    {
                        "event": "peer_leave",
                        "device_tag": peer.device_tag,
                        "vpn_ip": str(peer.vpn_ip),
                        "created_at": time.time(),
                    },
                )
            except Exception:
                pass


def server_program():
    import argparse

    parser = argparse.ArgumentParser(description="Multi-peer VPN server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8019)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument(
        "--nat-interface",
        default=None,
        help="outbound NAT interface (auto-detected from the default route)",
    )
    parser.add_argument("--vpn-network", default="10.8.0.0/24")
    parser.add_argument("--server-ip", default="10.8.0.1")
    parser.add_argument("--chat-port", type=int, default=8080)
    parser.add_argument("--chat-agent-port", type=int, default=48271)
    parser.add_argument("--kafka-bootstrap", default=None)
    parser.add_argument(
        "--key-exchange",
        choices=("auto",) + available_key_exchanges(),
        default="auto",
        help="require this key exchange, or accept the client's selection",
    )
    parser.add_argument(
        "--cipher",
        choices=("auto",) + SUPPORTED_CIPHERS,
        default="auto",
        help="require this cipher, or accept the client's selection",
    )
    args = parser.parse_args()

    if args.kafka_bootstrap:
        os.environ["KAFKA_BOOTSTRAP_SERVERS"] = args.kafka_bootstrap

    if args.debug:
        print(f"[server] available key exchanges: {', '.join(available_key_exchanges())}")

    kafka_bus = KafkaBus()
    device_directory = KafkaDeviceDirectory(kafka_bus)
    registry = PeerRegistry(args.vpn_network, args.server_ip)
    tun, ifname = create_tun("vpn0")
    set_if_up(ifname, f"{args.server_ip}/{registry.network.prefixlen}")
    setup_server_nat(args.nat_interface)

    chat_service = ChatService(kafka_bus, device_directory, registry, args.chat_agent_port)
    chat_http_server, _ = run_chat_service(chat_service, args.server_ip, args.chat_port)

    stop_event = threading.Event()
    tun_write_lock = threading.Lock()
    router_thread = threading.Thread(
        target=start_server_tun_router,
        args=(tun, registry, stop_event, 1 if args.debug else 0),
        daemon=True,
        name="server-tun-router",
    )
    router_thread.start()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(128)
    listener.settimeout(1.0)
    print(f"Server listening on {args.host}:{args.port}; TUN {ifname}={args.server_ip}")

    try:
        while not stop_event.is_set():
            try:
                conn, address = listener.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(
                target=_serve_peer,
                args=(
                    conn,
                    address,
                    registry,
                    tun,
                    tun_write_lock,
                    stop_event,
                    args.key_exchange,
                    args.cipher,
                    device_directory,
                    kafka_bus,
                    1 if args.debug else 0,
                ),
                daemon=True,
                name=f"peer-{address[0]}:{address[1]}",
            )
            thread.start()
    except KeyboardInterrupt:
        print("\n[server] shutting down")
    finally:
        stop_event.set()
        try:
            listener.close()
        except OSError:
            pass
        for peer in registry.snapshot():
            peer.close()
        chat_http_server.should_exit = True
        close_tun(tun)


if __name__ == "__main__":
    server_program()
