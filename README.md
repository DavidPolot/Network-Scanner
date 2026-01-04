A multi-threaded network scanner wrtitten in Python that detects open, closed and filtered TCP ports using socket connections

## Features
- Scans single ports, and port ranges
- Identifies open, closed, and filtered ports
- Input validation for ports (1-65535)
- Timeout handling to prevent hanging scans
- Clean, readable output

The scanner uses the socket python module to attempt TCP connections to each port, these are excecuted in a seperate thread to improve performance.
dynamic loading, so scanning a large range doesn't use up a lot of memory.

Port states:
- Open: TCP connection succeeds
- Closed: connection refused
- filtered: connection timed out or is blocked by a firewall.

usage: 
Please input the string in the terminal in this way:
python network_scanner.py -t (target) -p (single ports or range) --threads (number of threads) --timeout (how long it takes to send a signal)

## Future Improvements and Additions
- UDP scanning support
- service/version detection
- Exporting results to CSV or JSON

## Skills Demonstrated
- Python programming
- Network Fundamentals (TCP/IP)
- Multithreading and concurrency
- Input validation and error handling
- Secure and ethical coding practices

