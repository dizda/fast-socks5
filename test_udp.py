import socket
import socks
import dns.message  # pip install dnspython
import os
import time

def create_dns_query(domain):
    # Create a DNS query message
    query = dns.message.make_query(domain, 'A')
    return query.to_wire()

def parse_dns_response(response_data):
    # Parse the DNS response
    response = dns.message.from_wire(response_data)
    return response

def send_dns_query(sock, domain, dns_server=("8.8.8.8", 53)):
    """Send a single DNS query and return the response"""
    print(f"\n🔍 Querying {domain} via {dns_server[0]}...")
    
    try:
        # Create and send query
        query_data = create_dns_query(domain)
        sock.sendto(query_data, dns_server)
        
        # Receive response with timeout
        sock.settimeout(5.0)
        data, addr = sock.recvfrom(1024)
        
        # Parse and display response
        response = parse_dns_response(data)
        print(f"✅ Response from {addr}:")
        
        # Print A records
        ip_addresses = []
        for answer in response.answer:
            for item in answer.items:
                if item.rdtype == dns.rdatatype.A:
                    ip_addresses.append(str(item))
        
        if ip_addresses:
            print(f"   IP Addresses: {', '.join(ip_addresses)}")
        else:
            print("   No A records found")
            
        return True
        
    except socket.timeout:
        print(f"❌ Timeout querying {domain}")
        return False
    except Exception as e:
        print(f"❌ Error querying {domain}: {e}")
        return False

# Read proxy configuration from environment variables
PROXY_HOST = os.getenv('SOCKS_HOST', 'localhost')
PROXY_PORT = int(os.getenv('SOCKS_PORT', '1080'))
PROXY_USERNAME = os.getenv('SOCKS_USERNAME')
PROXY_PASSWORD = os.getenv('SOCKS_PASSWORD')

print(f"🔗 Using SOCKS5 proxy: {PROXY_HOST}:{PROXY_PORT}")
if PROXY_USERNAME:
    print(f"🔐 Authentication: {PROXY_USERNAME}")
else:
    print("🔓 No authentication (anonymous)")

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

print("\n📡 Establishing SOCKS5 UDP association...")

try:
    # List of domains to query
    domains_to_query = [
        "google.com",
        "github.com", 
        "stackoverflow.com",
        "python.org",
        "rust-lang.org"
    ]
    
    # DNS servers to try
    dns_servers = [
        ("8.8.8.8", 53),      # Google DNS
        ("1.1.1.1", 53),      # Cloudflare DNS
        ("8.8.4.4", 53),      # Google DNS Secondary
    ]
    
    print(f"🚀 Sending {len(domains_to_query)} DNS queries through the same SOCKS pipe...")
    print("=" * 60)
    
    successful_queries = 0
    
    # Send multiple queries through the same SOCKS connection
    for i, domain in enumerate(domains_to_query, 1):
        print(f"\n[{i}/{len(domains_to_query)}]", end=" ")
        
        # Alternate between different DNS servers to show flexibility
        dns_server = dns_servers[i % len(dns_servers)]
        
        if send_dns_query(s, domain, dns_server):
            successful_queries += 1
        
        # Small delay between queries to be nice to DNS servers
        if i < len(domains_to_query):
            time.sleep(0.5)
    
    print("\n" + "=" * 60)
    print(f"✨ Completed: {successful_queries}/{len(domains_to_query)} queries successful")
    print("💡 All queries used the same SOCKS5 UDP association!")

except Exception as e:
    print(f"❌ Connection error: {e}")
finally:
    print("\n🔒 Closing SOCKS connection...")
    s.close()
