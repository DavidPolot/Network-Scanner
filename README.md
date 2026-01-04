### A multi-threaded network scanner written in Python that detects open, closed and filtered TCP ports using socket connections

### DISCLAIMER
This tool is only for educational use and authorized use only

## Features
- Scans single ports and port ranges
- Identifies open, closed, and filtered ports
- Input validation for ports (1-65535)
- Timeout handling to prevent hanging scans
- Clean, readable output

## Disclaimer
The scanner uses the socket Python module to attempt TCP connections to each port; these are executed in a separate thread to improve performance.
dynamic loading, so scanning a large range doesn't use up a lot of memory.

## Port states:
- Open: TCP connection succeeds
- Closed: connection refused
- filtered: connection timed out or is blocked by a firewall.

## usage: 
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

## Technical Notes

- Port state detection is based on `socket.connect_ex`, which returns OS-specific error codes.
- The scanner explicitly handles `ECONNREFUSED` (and Windows error code `10061`) to accurately classify **closed** ports.
- Timeout, unreachable, and firewall-blocked responses are classified as **filtered** to avoid false positives.
- Thread count is bounded to prevent resource exhaustion during large scans.

