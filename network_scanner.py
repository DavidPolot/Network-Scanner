import argparse
import socket
import sys
#copy and paste this command to run the script with desired parameters
#python network_scanner.py -t 10.4.138.62 -p 1-65535 --threads 200 --timeout 0.1
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

from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_ports_threaded(target, ports, timeout, thread_count):
    open_ports = []

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        # Submit all port scans to the thread pool
        future_to_port = {
            executor.submit(scan_port, target, port, timeout): port
            for port in ports
        }

        # Collect results as they finish
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open = future.result()
                if is_open:
                    open_ports.append(port)
            except Exception:
                pass

    return open_ports

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


def scan_port(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except:
        sock.close()
        return False
    
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

    try:
        open_ports = scan_ports_threaded(target, ports, timeout, thread_count)
        if open_ports:
            print("Open ports:", open_ports)
            #get hostname from ip
            ip = socket.gethostbyname(target)
            hostname = hostname_from_ip(ip)
            if hostname:
                print(f"Hostname for IP {ip}: {hostname}")
            
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




