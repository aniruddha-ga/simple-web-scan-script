# Simple Vulnerability Scanner

## Overview

The Simple Vulnerability Scanner is a Python-based tool designed to help identify potential vulnerabilities in a target system. It performs port scanning, checks for common HTTP vulnerabilities, and can query multiple CVE (Common Vulnerabilities and Exposures) sources to find known vulnerabilities associated with open ports.

## Features

- **Port Scanning**: Scans the target for open ports within a specified range.
- **HTTP Vulnerability Check**: Detects common HTTP issues such as default pages.
- **CVE Checks**: Optionally checks for known vulnerabilities using:
  - NVD (National Vulnerability Database)
  - CVE Details

## Requirements

- Python 3.x
- Required Python libraries:
  - `nmap`
  - `requests`

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/vuln_scanner.git
   cd vuln_scanner
2. Install the required libraries:
   ```bash
    pip install python-nmap requests
    
## Usage

Run the scanner using the following command:

```bash
python vuln_scanner.py <target> -p <port_range> [--cve yes|no]
```

### Parameters

- `<target>`: IP address or domain name of the target to scan.
- `-p <port_range>`: Specify the range of ports to scan (default: `1-1024`).
- `--cve yes|no`: Enable or disable CVE checks (default: `no`).

### Example

To scan a target with CVE checks enabled:

```bash
python vuln_scanner.py example.com -p 1-100 --cve yes
```

## CVE Source Selection

If CVE checks are enabled, you will be prompted to choose a CVE source:

1. **NVD (National Vulnerability Database)**
2. **CVE Details**

Enter the number corresponding to your choice to fetch vulnerabilities for the open ports.

## Important Notes

- **Permission**: Ensure you have explicit permission to scan any target system. Unauthorized scanning may violate laws and regulations.
- **Rate Limiting**: Be mindful of API rate limits when querying CVE sources.

## Contributing

Contributions are welcome! Feel free to fork the repository, make changes, and submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Nmap](https://nmap.org/) - For port scanning functionality.
- [NVD](https://nvd.nist.gov/) - For providing a comprehensive CVE database.
- [CVE Details](https://www.cvedetails.com/) - For additional CVE information.