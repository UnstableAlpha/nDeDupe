# Nessus Scan Merger
A Python utility designed to merge and deduplicate Tenable Nessus vulnerability scan results. Particularly useful for large infrastructure assessments where multiple scans are conducted across different time periods or network segments.


## Features
- Merges multiple .nessus files into a single consolidated output
- Deduplicates vulnerability findings
- Identifies FQDN mismatches for the same IP addresses
- Maintains scan data integrity
- Includes comprehensive logging
- Exports in standard .nessus format

## Requirements
- Python 3.7+
- No external dependencies required

## Installation
```bash
git clone https://github.com/UnstableAlpha/nDeDupe.git
cd nessus-merger
chmod +x nessus_merger.py
```

## Usage
### Basic Usage:
```bash
python nDeDupe.py /path/to/nessus/files --output merged_results.nessus
```

## Output Files
The script generates:
- Merged .nessus file with consolidated results
- FQDN mismatches report (if mismatches found)
- Processing log file

## Security
This tool is designed for use by security professionals during authorised security assessments. Ensure you have appropriate permissions before scanning any infrastructure.

## Licence
Released under the MIT Licence.

## Contributing
Contributions welcome via pull requests. Please ensure you follow the existing code style and include appropriate tests and documentation.

## Author
James B - SilvaTech
