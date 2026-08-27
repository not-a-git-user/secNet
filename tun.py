import fcntl, struct, subprocess

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

def create_tun(name='vpn0'):
    #cleanup of old
    try:
        import subprocess
        subprocess.run(['ip', 'tuntap', 'del', 'mode', 'tun', name], 
                      stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    except Exception:
        pass

    #trying diff names in case some are busy
    names_to_try = [name] + [f'tun{i}' for i in range(10)]
    last_error = None
    
    for try_name in names_to_try:
        try:
            tun = open('/dev/net/tun', 'r+b', buffering=0)
            ifr = struct.pack('16sH', try_name.encode(), IFF_TUN | IFF_NO_PI)
            try:
                fcntl.ioctl(tun, TUNSETIFF, ifr)
                return tun, try_name
            except OSError as e:
                tun.close()
                if e.errno != 16:
                    raise
                last_error = e
        except Exception as e:
            last_error = e
            continue
    
    raise last_error or OSError("Could not create TUN device")

def set_if_up(ifname, cidr="10.0.0.2/24", mtu=1400):
    subprocess.run(["ip", "addr", "add", cidr, "dev", ifname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "dev", ifname, "mtu", str(mtu)], check=False)
    subprocess.run(["ip", "link", "set", "dev", ifname, "up"], check=True)

def close_tun(tun):
    try:
        tun.close()
    except Exception:
        pass
