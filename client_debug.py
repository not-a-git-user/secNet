import sys
import socket
import signal
import threading
import time

import packet_manager
from packet_manager import (
    create_tun,
    set_if_up,
    setup_client_routing,
    restore_client_routing,
    recv_frames_from_socket,
    parse_ip_packet,
    packet_endpoints,
    close_tun,
)
from protocol import send_frame
import client

def start_client_packet_manager_debug(sock: socket.socket, session, tun_name, tun_ip, debug_level=0, on_ready=None):
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
                                print(f"[DEBUG EGRESS DROP] spoofed source {source} -> {dest}")
                                print(f"[DEBUG EGRESS DROP RAW] {packet.hex()}")
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
        print(f"[client] TUN {ifname} up as {tun_ip}; forwarding started (DEBUG MODE)")
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
        restore_client_routing(original_route)
        if tun is not None:
            close_tun(tun)

if __name__ == "__main__":
    # Monkey-patch the packet manager to use our debug version
    packet_manager.start_client_packet_manager = start_client_packet_manager_debug
    
    # Run the normal client program
    client.client_program()
