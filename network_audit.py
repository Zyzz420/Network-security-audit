# network_audit.py
import nmap

def audit_network(ip_range):
    try:
        nm = nmap.PortScanner()
        print(f"Starting network audit for {ip_range}...")
        nm.scan(ip_range, arguments='-sS')
        
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"Status: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                if ports:
                    print(f"Open ports: {sorted(ports)}")
                    for port in ports:
                        service = nm[host][proto][port]['name']
                        print(f"  - Port {port}: {service}")
                else:
                    print("Open ports: None")
        
        # Customer-focused recommendations
        print("\nSecurity Recommendations:")
        print("- Close unused ports (e.g., 631, 3306, 5432) to reduce attack surface.")
        print("- Enable encryption (e.g., TLS) for services like MySQL (3306) or PostgreSQL (5432).")
        print("- Regularly monitor open ports to protect customer data.")
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        print("Ensure nmap is installed and you have root privileges.")

if __name__ == "__main__":
    audit_network("127.0.0.1")