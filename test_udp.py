import socket
import socks
import dns.message  # pip install dnspython
import os

def create_dns_query(domain):
    # Create a DNS query message
    query = dns.message.make_query(domain, 'A')
    return query.to_wire()

def parse_dns_response(response_data):
    # Parse the DNS response
    response = dns.message.from_wire(response_data)
    return response

# Read proxy configuration from environment variables
PROXY_HOST = os.getenv('SOCKS_HOST', 'localhost')
PROXY_PORT = int(os.getenv('SOCKS_PORT', '1080'))
PROXY_USERNAME = os.getenv('SOCKS_USERNAME')
PROXY_PASSWORD = os.getenv('SOCKS_PASSWORD')

print(f"Using SOCKS5 proxy: {PROXY_HOST}:{PROXY_PORT}")
if PROXY_USERNAME:
    print(f"Authentication: {PROXY_USERNAME}")
else:
    print("No authentication (anonymous)")

# Setup SOCKS connection with username/password authentication
s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)

# Set proxy with optional username and password authentication
if PROXY_USERNAME and PROXY_PASSWORD:
    # With authentication
    s.setproxy(
        socks.SOCKS5,           # SOCKS version
        PROXY_HOST,             # SOCKS server address
        PROXY_PORT,             # SOCKS server port
        rdns=True,              # Resolve DNS remotely
        username=PROXY_USERNAME, # Username for authentication
        password=PROXY_PASSWORD  # Password for authentication
    )
else:
    # Without authentication
    s.setproxy(
        socks.SOCKS5,           # SOCKS version
        PROXY_HOST,             # SOCKS server address
        PROXY_PORT,             # SOCKS server port
        rdns=True               # Resolve DNS remotely
    )

try:
    # Send DNS query for google.com
    query_data = create_dns_query("google.com")
    s.sendto(query_data, ("8.8.8.8", 53))  # Google's DNS server

    # Receive response
    data, addr = s.recvfrom(1024)

    # Parse and print response
    response = parse_dns_response(data)
    print(f"Response from {addr}:")
    print(response)

    # Print A records
    for answer in response.answer:
        for item in answer.items:
            if item.rdtype == dns.rdatatype.A:
                print(f"IP Address: {item}")

except Exception as e:
    print(f"Error: {e}")
finally:
    s.close()
