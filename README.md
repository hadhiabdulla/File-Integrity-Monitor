# File Integrity Monitor

A comprehensive Python-based file integrity monitoring system designed for educational cybersecurity purposes. This tool helps cybersecurity professionals and enthusiasts understand file system security, intrusion detection, and data integrity concepts.

## Description

The File Integrity Monitor is a security tool that continuously watches specified directories and files for any unauthorized changes. It uses cryptographic hashing, file metadata analysis, and real-time monitoring to detect potential tampering or malicious activities.

## Features

- **Real-time File Monitoring**: Continuous surveillance of specified directories
- **Hash-based Integrity Checking**: Uses SHA-256, SHA-1, and MD5 for file verification
- **Metadata Analysis**: Monitors file size, permissions, timestamps, and ownership
- **Recursive Directory Scanning**: Monitors nested directories and subdirectories
- **Real-time Console Alerts**: Immediate notifications of detected changes
- **Detailed Log Files**: Comprehensive logging with timestamps and details
- **Report Generation**: Generate text and JSON formatted reports for analysis
- **File Pattern Filtering**: Include/exclude files based on patterns

## Requirements

- Python 3.7+
- Required Python packages:
  - `watchdog>=2.1.0` (for real-time monitoring)
  - `hashlib` (built-in)
  - `os` (built-in)
  - `json` (built-in)
  - `logging` (built-in)
  - `datetime` (built-in)
  - `argparse` (built-in)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/hadhiabdulla/File-Integrity-Monitor.git
cd File-Integrity-Monitor
```

2. Install Python dependencies:
```bash
pip install watchdog
```

3. Make scripts executable (Linux/macOS):
```bash
chmod +x fim.py
```

## Usage

### Basic Usage

#### Create Initial Baseline
```bash
# Create baseline for current directory
python fim.py --create-baseline

# Create baseline for specific directory
python fim.py -d /path/to/monitor --create-baseline
```

#### Check File Integrity
```bash
# Check integrity against baseline for current directory
python fim.py --check

# Check integrity for specific directory
python fim.py -d /path/to/monitor --check
```

#### Real-time Monitoring
```bash
# Start real-time monitoring (requires watchdog)
python fim.py --real-time

# Monitor specific directory in real-time
python fim.py -d /path/to/monitor --real-time
```

### Advanced Usage

```bash
# Monitor with specific hash algorithm
python fim.py -d /path/to/monitor --hash sha256 --check

# Monitor with file filtering
python fim.py -d /path/to/monitor --include "*.txt,*.doc" --exclude "*.tmp,*.log" --check

# Generate reports
python fim.py -d /path/to/monitor --check --output report.txt
python fim.py -d /path/to/monitor --check --output report.json --report-format json

# Verbose monitoring
python fim.py -d /path/to/monitor --check --verbose
```

## Command Line Options

- `-d, --directory`: Directory to monitor (default: current directory)
- `--hash`: Hash algorithm (md5, sha1, sha256) - default: sha256
- `-v, --verbose`: Enable verbose logging
- `--baseline`: Baseline file path (default: fim_baseline.json)
- `--include`: File patterns to include (comma-separated)
- `--exclude`: File patterns to exclude (comma-separated)
- `--create-baseline`: Create new baseline
- `--check`: Check integrity against baseline
- `--real-time`: Start real-time monitoring
- `-o, --output`: Output file for reports
- `--report-format`: Report format (text, json) - default: text

## File Structure

```
File-Integrity-Monitor/
├── fim.py                   # Main monitoring script
├── fim_baseline.json        # Baseline file (created automatically)
├── README.md               # This file
└── .gitignore              # Git ignore file
```

## How It Works

1. **Baseline Creation**: Creates cryptographic fingerprints of monitored files
2. **Continuous Monitoring**: Uses file system events to detect changes
3. **Change Detection**: Compares current state against baseline
4. **Alerting and Reporting**: Logs changes and generates reports

## Sample Output

```
File Integrity Monitor v1.0
===========================
[2025-08-27 12:47:32] INFO: File Integrity Monitor Started
[2025-08-27 12:47:32] INFO: Scanning directory: /home/user/documents
[2025-08-27 12:47:32] INFO: Baseline loaded: 1,247 files
[2025-08-27 12:47:45] WARNING: NEW FILE: /home/user/documents/new_document.txt
[2025-08-27 12:48:12] CRITICAL: DELETED: /home/user/documents/important.key
[2025-08-27 12:48:20] WARNING: MODIFIED: /home/user/documents/config.ini
```

## Educational Purpose

This tool helps cybersecurity professionals and enthusiasts understand:
- **File System Security**: Learn how files can be monitored and protected
- **Cryptographic Hashing**: Understand hash functions and their security applications
- **Intrusion Detection**: Grasp the principles of detecting unauthorized system changes
- **Incident Response**: Practice responding to detected security events
- **Digital Forensics**: Learn to maintain audit trails and analyze security incidents

## Security Considerations

⚠️ **Important Security Notes**
- **Baseline Security**: Store baselines in secure, read-only locations
- **Log Protection**: Protect log files from unauthorized access
- **Performance Impact**: Monitor system resources during intensive scanning
- **Privilege Requirements**: Run with appropriate permissions for monitored directories

## Best Practices

1. **Regular Baseline Updates**: Update baselines after authorized changes
2. **Log Rotation**: Implement log rotation to manage disk space
3. **Testing**: Test monitoring setup in non-production environments first
4. **Documentation**: Document all configuration changes and exceptions
5. **Incident Response**: Develop procedures for responding to alerts

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with proper documentation
4. Add tests for new features
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

**EDUCATIONAL USE ONLY**: This software is provided for educational and authorized monitoring purposes only. Users are responsible for obtaining proper authorization before monitoring any systems and complying with all applicable laws and regulations.

## Contact

For questions, issues, or educational inquiries:
- Open an issue on GitHub
- Check the documentation wiki
- Review existing issues before posting
