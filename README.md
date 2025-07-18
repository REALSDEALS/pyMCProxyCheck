# pyMCProxyCheck

A Python utility to maintain a local database of Microsoft Azure Service Tag IP prefixes and ASNs, and to quickly verify whether an IP address is routed through Microsoft’s infrastructure (e.g. Azure proxies).

## Features

- **Automated Updates**  
  Downloads the official Microsoft “Azure IP Ranges & Service Tags” JSON once a week (or on demand) and rebuilds a local SQLite database.
- **Trusted Lists**  
  - **Service Tags**: stores every tag name and its IP prefixes (`tags(tag, prefix)` table).  
  - **ASNs**: derives and stores the Autonomous System Numbers behind each prefix (`asns(asn)` table).
- **CSV Exports**  
  - `microsoft_trusted_prefixes.csv` (columns: `tag`, `prefix`)  
  - `microsoft_asns.csv` (column: `asn`)
- **IP Check CLI**  
  Command-line flag to check one or more IP addresses and report if they’re “Trusted” or “Untrusted,” with matching prefix/ASN details.

## How to Use

1. **Install/Clone the repository**:
```bash
git clone https://github.com/REALSDEALS/pyMCProxyCheck.git
cd pyMCProxyCheck
```
2. **Install dependencies**:
```bash
pip install -r requirements.txt
```
3. **Run the script**:
```bash
python microsoft_proxies.py
```
4. **Build database of IP addresses**:
```bash
python microsoft_proxies.py --update
```
5. **Check IP addresses**:
```bash
python microsoft_proxies.py --check-ip <ip_address1> <ip_address2> ...
```
## Example Usage
```bash
python microsoft_proxies.py --check-ip 1.1.1.1 
```
## Output
```plaintext
Trusted or Untrusted
```

## For Exporting Data
To export the trusted prefixes and ASNs to CSV files, run:
```bash
python microsoft_proxies.py --export
```
## Output Files
- `microsoft_trusted_prefixes.csv`: Contains all trusted prefixes with their associated tags.
- `microsoft_asns.csv`: Contains all ASNs derived from the prefixes.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Copyright
© 2025 REALSDEALS  
You are free to use, modify, and distribute this software, provided that the original license and copyright notice are included in all copies or substantial portions of the software.