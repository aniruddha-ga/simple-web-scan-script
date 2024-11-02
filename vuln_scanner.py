import nmap
import requests
import argparse

import nmap

def scan_ports(target, port_range):
    print(f"Scanning {target} for open ports...")
    nm = nmap.PortScanner()
    try:
        # Use TCP connect scan with --unprivileged to avoid raw packet errors
        nm.scan(target, arguments=f"-p {port_range}")
        print("nmap scan info:", nm.scaninfo())
    except Exception as e:
        print(f"Error during nmap scan: {e}")
        return []

    # Check if the scan returned any hosts
    if target not in nm.all_hosts():
        print(f"Target {target} not found in scan results.")
        return []

    open_ports = []
    for proto in nm[target].all_protocols():
        ports = nm[target][proto].keys()
        for port in sorted(ports):
            if nm[target][proto][port]['state'] == 'open':
                open_ports.append(port)
                print(f"Open port: {port}")
                
    return open_ports

def check_http_vulnerabilities(target):
    print(f"Checking for common HTTP vulnerabilities on {target}...")
    try:
        response = requests.get(target)
        if response.status_code == 200:
            print("HTTP Status: 200 OK")
            if "default" in response.text.lower():
                print("Warning: Default page detected.")
        else:
            print(f"HTTP Status: {response.status_code}")
    except requests.exceptions.ConnectTimeout:
        print(f"Connection to {target} timed out.")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to {target}: {e}")

def check_cve(target, open_ports, source):
    if source == 'nvd':
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=port "
    elif source == 'cve_details':
        base_url = "https://www.cvedetails.com/api/v1/vulnerability/search?port "
        # Replace Token for CVE Details to work
        headers = {'Authorization': 'Bearer REPLACE_THIS_WITH_YOUR_ACCESS_TOKEN'}
    
    print(f"Checking for known vulnerabilities for {target} using {source}...")
    
    for port in open_ports:
        url = f"{base_url}{port}"
        try:
            # Adjust the following based on the API response structure
            if source == 'nvd':
                response = requests.get(url)
                data = response.json()
                for item in data['result']['CVE_Items']:
                    print(f"Found CVE: {item['cve']['CVE_data_meta']['ID']} - {item['cve']['description']['description_data'][0]['value']}")
            elif source == 'cve_details':
                response = requests.get(url, headers)
                data = response.json()
                for item in data:
                    print(f"Found CVE: {item['id']} - {item['summary']}")

        except requests.exceptions.RequestException as e:
            print(f"Error fetching CVE data: {e}")

def main():
    parser = argparse.ArgumentParser(description='Simple Vulnerability Scanner')
    parser.add_argument('target', type=str, help='Target IP or domain to scan')
    parser.add_argument('-p', '--port', type=str, default='1-1024', help='Port range to scan (default: 1-1024)')
    parser.add_argument('--cve', type=str, choices=['yes', 'no'], default='no', help='Enable CVE check (default: no)')

    args = parser.parse_args()

    open_ports = scan_ports(args.target, args.port)
    check_http_vulnerabilities(f"http://{args.target}")

    if args.cve.lower() == 'yes' and open_ports:
        print("Choose a CVE source for port details search:")
        print("1. NVD (National Vulnerability Database)")
        print("2. CVE Details")
        choice = input("Enter the number of your choice (1 or 2): ")

        if choice == '1':
            check_cve(args.target, open_ports, 'nvd')
        elif choice == '2':
            check_cve(args.target, open_ports, 'cve_details')
        else:
            print("Invalid choice. Skipping CVE checks.")

if __name__ == "__main__":
    main()