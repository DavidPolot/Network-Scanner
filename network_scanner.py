import argparse
import socket
import sys
import ipaddress
import errno
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_ports(ports_str):
    ports = set()
    for part in ports_str.split(','):
        part = part.strip()
        if not part:
            continue

        try:
            if '-' in part:
                start, end = part.split('-', 1)
                start = int(start)
                end = int(end)
                if start > end:
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        except ValueError:
            print(f"Invalid port specification: {part}")
            sys.exit(1)

    valid_ports = [p for p in ports if 1 <= p <= 65535]
    if not valid_ports:
        print("No valid ports to scan.")
        sys.exit(1)

    return sorted(valid_ports)


def chunked(iterable, size):
    for i in range(0, len(iterable), size):
        yield iterable[i:i + size]


# scanning

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
            return "filtered"


def scan_ports_threaded(target, ports, timeout, thread_count, chunk_size=None):
    if chunk_size is None:
        chunk_size = max(1, len(ports) // (thread_count * 4))

    open_ports = []
    closed_ports = []
    filtered_ports = []

    total = len(ports)
    completed = 0

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        for port_chunk in chunked(ports, chunk_size):
            future_to_port = {
                executor.submit(scan_port, target, port, timeout): port
                for port in port_chunk
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1

                if completed % 500 == 0 or completed == total:
                    percent = (completed / total) * 100
                    print(
                        f"Scanning ports: {completed}/{total} ({percent:.1f}%)",
                        end="\r",
                        flush=True
                    )

                try:
                    status = future.result()
                    if status == "open":
                        open_ports.append(port)
                    elif status == "closed":
                        closed_ports.append(port)
                    else:
                        filtered_ports.append(port)
                except Exception:
                    filtered_ports.append(port)

    print()
    return open_ports, closed_ports, filtered_ports


# banner grabbing

def grab_banner(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner
    except Exception:
        return None
    finally:
        sock.close()


# DNS stuff

def hostname_from_ip(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None


def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private


# CLI stuff

def create_parser():
    parser = argparse.ArgumentParser(description="A simple threaded port scanner.")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="1-1024")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=1)
    return parser


# MAIN

if __name__ == "__main__":
    parser = create_parser()
    args = parser.parse_args()

    target = args.target
    ports = parse_ports(args.ports)
    timeout = args.timeout
    thread_count = args.threads

    # HIGH-IMPACT FIX #1: thread bounds
    if thread_count < 1 or thread_count > 1000:
        print("Thread count must be between 1 and 1000")
        sys.exit(1)

    print(f"Target: {target}")

    # HIGH-IMPACT FIX #2: invalid hostname
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Invalid target hostname or IP address")
        sys.exit(1)

    if not is_private_ip(ip):
        hostname = hostname_from_ip(ip)
        if hostname:
            print(f"Reverse DNS: {hostname}")
        else:
            print("No reverse DNS found")
    else:
        print("Private IP detected — skipping reverse DNS")

    print(f"Ports: {len(ports)}")
    print(f"Threads: {thread_count}")
    print(f"Timeout: {timeout}s\n")

    try:
        open_ports, closed_ports, filtered_ports = scan_ports_threaded(
            target, ports, timeout, thread_count
        )

        print(f"\nOpen ports ({len(open_ports)}): {open_ports}")
        print(f"Closed ports: {len(closed_ports)}")
        print(f"Filtered ports: {len(filtered_ports)}")

        if open_ports:
            for port in open_ports:
                banner = grab_banner(target, port, timeout)
                if banner:
                    print(f"Port {port} banner: {banner}")
        else:
            print("No open ports found.")

    except KeyboardInterrupt:
        print("\nScan cancelled by user.")
    except Exception as e:
        print("Scan failed:", e)




