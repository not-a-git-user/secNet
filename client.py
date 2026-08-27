import socket
import threading
import time
import subprocess
import sys
import urllib.request
from pathlib import Path

from handshake import available_key_exchanges, client_handshake
from encryptDecrypt import SUPPORTED_CIPHERS
from chat.identity import DeviceIdentity


def client_program():
    import argparse

    parser = argparse.ArgumentParser(description="VPN client")
    parser.add_argument("--host", required=True, help="VPN server address")
    parser.add_argument("--port", type=int, default=8019)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument(
        "--device-key",
        default="~/.vpn1/device-ed25519.key",
        help="persistent Ed25519 device key used for authentication",
    )
    parser.add_argument("--chat-port", type=int, default=8080)
    parser.add_argument("--chat-agent-port", type=int, default=48271)
    parser.add_argument("--chat-state-dir", default="~/.vpn1/chat")
    parser.add_argument("--no-chat-agent", action="store_true")
    parser.add_argument(
        "--key-exchange",
        "--exchange-protocol",
        dest="key_exchange",
        choices=available_key_exchanges(),
        default="ecdh",
        help="key exchange used for this session",
    )
    parser.add_argument(
        "--cipher",
        choices=SUPPORTED_CIPHERS,
        default="aes-256-gcm",
        help="authenticated cipher used for this session",
    )
    args = parser.parse_args()

    agent_process = None

    def start_chat_agent():
        nonlocal agent_process
        if not args.no_chat_agent:
            agent_process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "chat.chat_agent",
                    "--device-key",
                    str(Path(args.device_key).expanduser()),
                    "--state-dir",
                    str(Path(args.chat_state_dir).expanduser()),
                    "--port",
                    str(args.chat_agent_port),
                    "--origin",
                    f"http://10.0.0.1:{args.chat_port}",
                ],
                stdout=None if args.debug else subprocess.DEVNULL,
                stderr=None if args.debug else subprocess.DEVNULL,
                cwd=str(Path(__file__).parent),
            )
            deadline = time.time() + 3
            while time.time() < deadline:
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{args.chat_agent_port}/v1/status", timeout=0.2)
                    break
                except Exception:
                    if agent_process.poll() is not None:
                        print("[client] chat agent failed to start; chat will be unavailable")
                        agent_process = None
                        break
                    time.sleep(0.05)

    connected = threading.Event()
    client_socket = None
    attempt = 0
    while not connected.is_set():
        attempt += 1
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(10.0)
            sock.connect((args.host, args.port))
            client_socket = sock
            client_socket.settimeout(None)
            connected.set()
            if args.debug:
                print(f"[DEBUG] Connected on attempt #{attempt}")
        except Exception as exc:
            if args.debug:
                print(f"[DEBUG] Attempt #{attempt} failed: {exc}")
            sock.close()
            time.sleep(0.25)

    try:
        device_identity = DeviceIdentity.load_or_create(Path(args.device_key).expanduser())
        session = client_handshake(
            client_socket,
            args.key_exchange,
            args.cipher,
            device_identity=device_identity,
        )
        print(
            f"Handshake done; assigned VPN IP {session.vpn_ip}; "
            f"key exchange={session.key_exchange}, cipher={session.cipher}"
        )

        from packet_manager import start_client_packet_manager

        start_client_packet_manager(
            client_socket,
            session,
            tun_name="tun0",
            tun_ip=f"{session.vpn_ip}/24",
            debug_level=1 if args.debug else 0,
            on_ready=start_chat_agent,
        )
    except Exception as exc:
        print(f"Client error: {exc}")
        try:
            client_socket.close()
        except Exception:
            pass
    finally:
        if agent_process is not None:
            agent_process.terminate()
            try:
                agent_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                agent_process.kill()


if __name__ == "__main__":
    client_program()
