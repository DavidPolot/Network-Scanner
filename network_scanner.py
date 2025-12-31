import argparse
import socket
import sys
import ipaddress

#copy and paste this command to run the script with desired parameters
# use this ip for testing banner retrieval 45.33.32.156


def parse_ports(ports_str):
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start, end = part.split('-', 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def chunked(iterable, size):
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]

from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_ports_threaded(target, ports, timeout, thread_count, chunk_size=None):
    """
    Scan ports with threading, classifying each port as open, closed, or filtered.
    """
    if chunk_size is None:
        chunk_size = max(1, len(ports) // (thread_count * 4))  # dynamic chunk size

    open_ports = []
    closed_ports = []
    filtered_ports = []

    total = len(ports)
    completed = 0

    # Helper to split ports into chunks
    def chunked(iterable, size):
        for i in range(0, len(iterable), size):
            yield iterable[i:i + size]

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        for port_chunk in chunked(ports, chunk_size):
            future_to_port = {
                executor.submit(scan_port, target, port, timeout): port
                for port in port_chunk
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1

                # Progress update
                if completed % 500 == 0 or completed == total:
                    percent = (completed / total) * 100
                    print(f"Scanning ports: {completed}/{total} ({percent:.1f}%)", end="\r", flush=True)

                try:
                    status = future.result()
                    if status == "open":
                        open_ports.append(port)
                    elif status == "closed":
                        closed_ports.append(port)
                    elif status == "filtered":
                        filtered_ports.append(port)
                except Exception:
                    # If something unexpected happens, classify as filtered
                    filtered_ports.append(port)

    print()  # move to next line after completion
    return open_ports, closed_ports, filtered_ports



def create_parser():
    parser = argparse.ArgumentParser(description="A simple port scanner.")
    parser.add_argument("-t", "--target", help="Target IP address or hostname to scan.", required=True)
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports or ranges (e.g. 22,80,100-200).", default="1-1024")
    parser.add_argument("--threads", help="Number of threads to use (default: 10).", type=int, default=10)
    parser.add_argument("--timeout", help="Timeout in seconds for each port scan (default: 1).", type=float, default=1)
    return parser

#gather ip and port info
def port_info(target, port):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        ip = "Unknown"
    return ip, port

import errno
def scan_port(target, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((target, port))

            if result == 0:
                return "open"

            elif result == errno.ECONNREFUSED:
                return "closed"

            elif result in (errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH):
                return "filtered"

            else:
                return "filtered"

        except socket.timeout:
            return "filtered"

        except Exception:
            return "error"
    
#grab the banner of an open port (If available)
def grab_banner(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        sock.connect((target, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except:
        sock.close()
        return None
    
def hostname_from_ip(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None

def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private

if __name__ == "__main__":
    # If no args → run a quick local test and exit
    # if len(sys.argv) == 1:
    #     target = "127.0.0.1"
    #     ports = [22, 80, 443, 135, 445, 3389]
    #     timeout = 1
    #     thread_count = 50

    #     result = scan_ports_threaded(target, ports, timeout, thread_count)
    #     print("Local open ports:", result)
    #     print("Quick remote check (google.com:80):", scan_port("google.com", 80, 1))

    #     # display ip and port info
    #     ip, port = port_info("google.com", 80)
    #     print(f"google.com resolves to IP: {ip}, Port: {port}")
    #     sys.exit(0)

    # Otherwise → run full CLI scanner
    parser = create_parser()
    args = parser.parse_args()

    target = args.target
    ports_input = args.ports
    timeout = args.timeout
    thread_count = args.threads

    ports = parse_ports(ports_input)

    print(f"Target: {target}")
    print(f"Ports: {ports_input} -> {len(ports)} ports parsed (showing first 10): {ports[:10]}")
    print(f"Timeout: {timeout} seconds")
    print(f"Threads: {thread_count}")

    ip = socket.gethostbyname(target)

    print(f"Target IP: {ip}")

    if not is_private_ip(ip):
        hostname = hostname_from_ip(ip)
        if hostname:
            print(f"Reverse DNS: {hostname}")
        else:
            print("No reverse DNS found")
    else:
        print("Private IP detected — skipping reverse DNS")

    try:
        open_ports, closed_ports, filtered_ports = scan_ports_threaded(target, ports, timeout, thread_count)
        print(f"Open ports ({len(open_ports)}): {open_ports}")
        print(f"Closed ports: {len(closed_ports)}")
        print(f"Filtered ports: {len(filtered_ports)}")
        try:
            ip = socket.gethostbyname(target)
            hostname = hostname_from_ip(ip)

            if hostname:
                print(f"Reverse hostname for {ip}: {hostname}")
            else:
                print(f"No reverse hostname found for {ip}")

        except socket.gaierror:
            print("Could not resolve target to IP")

            
            # Grab banners for open ports
            for port in open_ports:
                banner = grab_banner(target, port, timeout)
                # display banner for port only if available
                if banner:
                    print(f"Port {port} banner: {banner}")
        else:
            print("No open ports found.")
    except KeyboardInterrupt:
        print("Scan cancelled by user.")
    except Exception as e:
        print("Scan failed:", e)




