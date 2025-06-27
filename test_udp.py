import socket
import socks
import dns.message  # pip install dnspython

def create_dns_query(domain):
    # Create a DNS query message
    query = dns.message.make_query(domain, 'A')
    return query.to_wire()

def parse_dns_response(response_data):
    # Parse the DNS response
    response = dns.message.from_wire(response_data)
    return response

# Setup SOCKS connection with username/password authentication
s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)

# Set proxy with username and password authentication
s.setproxy(
    socks.SOCKS5,           # SOCKS version
    "localhost",            # SOCKS server address
    1337,                   # SOCKS server port
    rdns=True,              # Resolve DNS remotely
    username="admin",       # Username for authentication
    password="password"     # Password for authentication
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
