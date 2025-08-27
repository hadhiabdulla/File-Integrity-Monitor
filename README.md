# File Integrity Monitor

A comprehensive Python-based file integrity monitoring system designed for educational cybersecurity purposes. This tool helps B.Tech CSE students understand file system security, intrusion detection, and data integrity concepts.

## Description

The File Integrity Monitor is a security tool that continuously watches specified directories and files for any unauthorized changes. It uses cryptographic hashing, file metadata analysis, and real-time monitoring to detect potential tampering or malicious activities.

## Features

- **Real-time File Monitoring**: Continuous surveillance of specified directories
- **Hash-based Integrity Checking**: Uses SHA-256, SHA-1, and MD5 for file verification
- **Metadata Analysis**: Monitors file size, permissions, timestamps, and ownership
- **Recursive Directory Scanning**: Monitors nested directories and subdirectories
- **Real-time Console Alerts**: Immediate notifications of detected changes
- **Detailed Log Files**: Comprehensive logging with timestamps and details
- **HTML Reports**: Generate formatted reports for analysis
- **Email Notifications**: Send alerts via email (configurable)

## Requirements

- Python 3.7+
- Required Python packages:
  - `watchdog>=2.1.0`
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
pip install -r requirements.txt
```

3. Make scripts executable (Linux/macOS):
```bash
chmod +x fim.py
```

## Usage

### Basic Usage

```bash
# Monitor current directory
python fim.py

# Monitor specific directory
python fim.py -d /path/to/monitor

# Create initial baseline
python fim.py -d /path/to/monitor --create-baseline

# Run monitoring with existing baseline
python fim.py -d /path/to/monitor --use-baseline
```

### Advanced Usage

```bash
# Monitor with specific hash algorithm
python fim.py -d /path/to/monitor --hash sha256

# Enable email notifications
python fim.py -d /path/to/monitor --email

# Monitor with file filtering
python fim.py -d /path/to/monitor --include "*.txt,*.doc" --exclude "*.tmp,*.log"

# Generate reports
python fim.py -d /path/to/monitor --report-format html --output report.html

# Real-time monitoring with verbose output
python fim.py -d /path/to/monitor --real-time --verbose
```

## Command Line Options

- `-d, --directory`: Directory/directories to monitor
- `-c, --config`: Configuration file path
- `-v, --verbose`: Enable verbose logging
- `--hash`: Hash algorithm (md5, sha1, sha256)
- `--real-time`: Enable real-time monitoring
- `--interval`: Scan interval in seconds
- `--include`: File patterns to include
- `--exclude`: File patterns to exclude
- `--create-baseline`: Create new baseline
- `--use-baseline`: Use existing baseline
- `-o, --output`: Output file path
- `--report-format`: Report format (text, html, json, csv)

## File Structure

```
File-Integrity-Monitor/
├── fim.py                   # Main monitoring script
├── lib/                     # Core library modules
│   ├── monitor.py           # File monitoring engine
│   ├── hasher.py            # Hash calculation utilities
│   ├── baseline.py          # Baseline management
│   ├── reporter.py          # Report generation
│   └── utils.py             # Utility functions
├── config/                  # Configuration files
├── data/                    # Data storage
│   ├── baselines/           # Baseline files
│   ├── logs/                # Log files
│   └── reports/             # Generated reports
├── tests/                   # Unit tests
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## How It Works

1. **Baseline Creation**: Creates cryptographic fingerprints of monitored files
2. **Continuous Monitoring**: Uses file system events to detect changes
3. **Change Detection**: Compares current state against baseline
4. **Alerting and Reporting**: Logs changes and sends notifications

## Sample Output

```
[2025-08-27 12:47:32] INFO: File Integrity Monitor Started
[2025-08-27 12:47:32] INFO: Monitoring directory: /home/user/documents
[2025-08-27 12:47:32] INFO: Baseline loaded: 1,247 files
[2025-08-27 12:47:45] WARNING: File modified: /home/user/documents/important.txt
[2025-08-27 12:48:12] CRITICAL: File deleted: /home/user/documents/secret.key
[2025-08-27 12:48:20] WARNING: New file created: /home/user/documents/unknown.exe
```

## Educational Purpose

This tool helps students understand:

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

---

**Note for B.Tech Students**: This project complements your cybersecurity coursework by providing hands-on experience with file integrity monitoring, intrusion detection, and digital forensics. Always practice in controlled environments and follow your institution's ethical guidelines.
