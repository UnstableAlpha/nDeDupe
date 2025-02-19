#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import os
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Dict, Set
import logging
from datetime import datetime

@dataclass
class NessusHost:
    ip: str
    fqdn: str
    vulnerabilities: List[dict]

class NessusMerger:
    def __init__(self, directory: str):
        self.directory = directory
        self.hosts: Dict[str, NessusHost] = {}
        self.fqdn_mismatches: Dict[str, Set[str]] = defaultdict(set)
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'nessus_merger_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def process_nessus_files(self) -> None:
        """Process all .nessus files in the specified directory."""
        nessus_files = [f for f in os.listdir(self.directory) if f.endswith('.nessus')]
        
        if not nessus_files:
            self.logger.error(f"No .nessus files found in {self.directory}")
            return

        for file in nessus_files:
            self.logger.info(f"Processing file: {file}")
            try:
                self._process_single_file(os.path.join(self.directory, file))
            except ET.ParseError as e:
                self.logger.error(f"Failed to parse {file}: {str(e)}")
            except Exception as e:
                self.logger.error(f"Error processing {file}: {str(e)}")

    def _process_single_file(self, file_path: str) -> None:
        """Process a single .nessus file and merge its data."""
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        for report_host in root.findall(".//ReportHost"):
            ip = ""
            fqdn = ""
            
            # Extract host properties
            for tag in report_host.findall("HostProperties/tag"):
                if tag.attrib.get('name') == 'host-ip':
                    ip = tag.text
                elif tag.attrib.get('name') == 'hostname':
                    fqdn = tag.text

            if not ip:
                self.logger.warning(f"Host found without IP in {file_path}")
                continue

            # Process vulnerabilities
            vulnerabilities = []
            for item in report_host.findall("ReportItem"):
                vuln = {
                    'plugin_id': item.attrib.get('pluginID'),
                    'port': item.attrib.get('port'),
                    'protocol': item.attrib.get('protocol'),
                    'severity': item.attrib.get('severity'),
                    'plugin_name': item.attrib.get('pluginName'),
                    'description': self._get_text(item.find('description')),
                    'solution': self._get_text(item.find('solution')),
                    'output': self._get_text(item.find('plugin_output'))
                }
                vulnerabilities.append(vuln)

            # Check for FQDN mismatches
            if ip in self.hosts and fqdn and self.hosts[ip].fqdn and fqdn != self.hosts[ip].fqdn:
                self.fqdn_mismatches[ip].add(self.hosts[ip].fqdn)
                self.fqdn_mismatches[ip].add(fqdn)
                self.logger.warning(f"FQDN mismatch found for IP {ip}: {self.hosts[ip].fqdn} vs {fqdn}")

            # Merge or add host
            if ip in self.hosts:
                self._merge_vulnerabilities(ip, vulnerabilities)
            else:
                self.hosts[ip] = NessusHost(ip=ip, fqdn=fqdn, vulnerabilities=vulnerabilities)

    def _get_text(self, element: ET.Element) -> str:
        """Safely extract text from an XML element."""
        return element.text if element is not None else ""

    def _merge_vulnerabilities(self, ip: str, new_vulns: List[dict]) -> None:
        """Merge new vulnerabilities with existing ones, avoiding duplicates."""
        existing_vulns = {self._vuln_key(v): v for v in self.hosts[ip].vulnerabilities}
        
        for vuln in new_vulns:
            key = self._vuln_key(vuln)
            if key not in existing_vulns:
                self.hosts[ip].vulnerabilities.append(vuln)
            else:
                # Update if new output is available
                if vuln['output'] and not existing_vulns[key]['output']:
                    existing_vulns[key]['output'] = vuln['output']

    def _vuln_key(self, vuln: dict) -> str:
        """Create a unique key for a vulnerability."""
        return f"{vuln['plugin_id']}_{vuln['port']}_{vuln['protocol']}"

    def export_results(self, output_file: str) -> None:
        """Export merged results to a new .nessus file."""
        # Create root element with proper format - NessusClientData_v2 (note the V is uppercase)
        root = ET.Element("NessusClientData_v2")
        # Add proper namespaces expected by Nessus 
        root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
        root.set("xmlns:nessus", "http://www.nessus.org/nessus_v2")
        
        # Create Report with proper name attribute
        report = ET.SubElement(root, "Report", name="Merged Scan Results")
        
        for host in self.hosts.values():
            report_host = ET.SubElement(report, "ReportHost", name=host.ip)
            host_properties = ET.SubElement(report_host, "HostProperties")
            
            # Add host properties
            ip_tag = ET.SubElement(host_properties, "tag", name="host-ip")
            ip_tag.text = host.ip
            if host.fqdn:
                fqdn_tag = ET.SubElement(host_properties, "tag", name="hostname")
                fqdn_tag.text = host.fqdn
            
            # Add vulnerabilities
            for vuln in host.vulnerabilities:
                report_item = ET.SubElement(report_host, "ReportItem",
                                          pluginID=vuln['plugin_id'],
                                          port=vuln['port'],
                                          protocol=vuln['protocol'],
                                          severity=vuln['severity'],
                                          pluginName=vuln['plugin_name'])
                
                if vuln['description']:
                    desc = ET.SubElement(report_item, "description")
                    desc.text = vuln['description']
                
                if vuln['solution']:
                    sol = ET.SubElement(report_item, "solution")
                    sol.text = vuln['solution']
                
                if vuln['output']:
                    output = ET.SubElement(report_item, "plugin_output")
                    output.text = vuln['output']

        # Write to file with proper XML declaration and format
        tree = ET.ElementTree(root)
        with open(output_file, 'wb') as f:
            f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
            tree.write(f, encoding='utf-8', xml_declaration=False)
        self.logger.info(f"Results exported to {output_file}")

        # Export FQDN mismatches if any were found
        if self.fqdn_mismatches:
            mismatch_file = f"fqdn_mismatches_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(mismatch_file, 'w') as f:
                f.write("FQDN Mismatches Report\n")
                f.write("=====================\n\n")
                for ip, fqdns in self.fqdn_mismatches.items():
                    f.write(f"IP: {ip}\n")
                    f.write("Associated FQDNs:\n")
                    for fqdn in fqdns:
                        f.write(f"  - {fqdn}\n")
                    f.write("\n")
            self.logger.info(f"FQDN mismatches exported to {mismatch_file}")

def main():
    # Set up argument parsing
    import argparse
    parser = argparse.ArgumentParser(description='Merge and deduplicate Nessus scan results')
    parser.add_argument('directory', help='Directory containing .nessus files')
    parser.add_argument('--output', '-o', default='merged_results.nessus',
                        help='Output file name (default: merged_results.nessus)')
    
    args = parser.parse_args()
    
    # Create and run merger
    merger = NessusMerger(args.directory)
    merger.process_nessus_files()
    merger.export_results(args.output)

if __name__ == "__main__":
    main()
