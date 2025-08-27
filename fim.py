#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
A comprehensive file integrity monitoring system for cybersecurity purposes.
Detects unauthorized changes using cryptographic hashing and real-time monitoring.
"""

import os
import sys
import json
import hashlib
import argparse
import logging
import time
from datetime import datetime
from pathlib import Path
import fnmatch

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

class FileIntegrityMonitor:
    """Main File Integrity Monitor class"""
    
    def __init__(self, directories, hash_algo='sha256', baseline_file=None, 
                 include_patterns=None, exclude_patterns=None, verbose=False):
        self.directories = directories if isinstance(directories, list) else [directories]
        self.hash_algo = hash_algo.lower()
        self.baseline_file = baseline_file or 'fim_baseline.json'
        self.include_patterns = include_patterns or ['*']
        self.exclude_patterns = exclude_patterns or []
        self.verbose = verbose
        self.baseline = {}
        self.changes_detected = []
        
        # Setup logging
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger(__name__)
        
    def calculate_file_hash(self, filepath):
        """Calculate hash for a file"""
        try:
            hash_obj = hashlib.new(self.hash_algo)
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except (IOError, OSError) as e:
            self.logger.error(f"Error calculating hash for {filepath}: {e}")
            return None
    
    def get_file_metadata(self, filepath):
        """Get file metadata"""
        try:
            stat = os.stat(filepath)
            return {
                'size': stat.st_size,
                'mtime': stat.st_mtime,
                'mode': stat.st_mode
            }
        except (IOError, OSError) as e:
            self.logger.error(f"Error getting metadata for {filepath}: {e}")
            return None
    
    def should_monitor_file(self, filepath):
        """Check if file should be monitored based on patterns"""
        filename = os.path.basename(filepath)
        
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return False
        
        for pattern in self.include_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
                
        return False
    
    def scan_directory(self, directory):
        """Recursively scan directory and create file signatures"""
        signatures = {}
        
        if not os.path.exists(directory):
            self.logger.error(f"Directory does not exist: {directory}")
            return signatures
            
        self.logger.info(f"Scanning directory: {directory}")
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                
                if not self.should_monitor_file(filepath):
                    continue
                    
                try:
                    file_hash = self.calculate_file_hash(filepath)
                    metadata = self.get_file_metadata(filepath)
                    
                    if file_hash and metadata:
                        signatures[filepath] = {
                            'hash': file_hash,
                            'metadata': metadata,
                            'scan_time': datetime.now().isoformat()
                        }
                        
                        if self.verbose:
                            self.logger.debug(f"Processed: {filepath}")
                            
                except Exception as e:
                    self.logger.error(f"Error processing {filepath}: {e}")
                    
        return signatures
    
    def create_baseline(self):
        """Create initial baseline of all monitored files"""
        self.logger.info("Creating baseline...")
        
        all_signatures = {}
        for directory in self.directories:
            signatures = self.scan_directory(directory)
            all_signatures.update(signatures)
        
        baseline_data = {
            'created': datetime.now().isoformat(),
            'hash_algorithm': self.hash_algo,
            'directories': self.directories,
            'files': all_signatures
        }
        
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline_data, f, indent=2)
            
            self.logger.info(f"Baseline created with {len(all_signatures)} files")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving baseline: {e}")
            return False
    
    def load_baseline(self):
        """Load existing baseline"""
        try:
            if not os.path.exists(self.baseline_file):
                self.logger.error(f"Baseline file not found: {self.baseline_file}")
                return False
                
            with open(self.baseline_file, 'r') as f:
                baseline_data = json.load(f)
            
            self.baseline = baseline_data.get('files', {})
            self.logger.info(f"Baseline loaded: {len(self.baseline)} files")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading baseline: {e}")
            return False
    
    def check_integrity(self):
        """Check current state against baseline"""
        if not self.baseline:
            self.logger.error("No baseline loaded. Create baseline first.")
            return False
            
        self.logger.info("Starting integrity check...")
        changes = []
        current_files = set()
        
        for directory in self.directories:
            signatures = self.scan_directory(directory)
            
            for filepath, current_sig in signatures.items():
                current_files.add(filepath)
                baseline_sig = self.baseline.get(filepath)
                
                if not baseline_sig:
                    changes.append({
                        'type': 'NEW_FILE',
                        'file': filepath,
                        'timestamp': datetime.now().isoformat()
                    })
                    self.logger.warning(f"NEW FILE: {filepath}")
                    
                elif current_sig['hash'] != baseline_sig['hash']:
                    changes.append({
                        'type': 'MODIFIED',
                        'file': filepath,
                        'timestamp': datetime.now().isoformat()
                    })
                    self.logger.warning(f"MODIFIED: {filepath}")
        
        baseline_files = set(self.baseline.keys())
        deleted_files = baseline_files - current_files
        
        for filepath in deleted_files:
            changes.append({
                'type': 'DELETED',
                'file': filepath,
                'timestamp': datetime.now().isoformat()
            })
            self.logger.critical(f"DELETED: {filepath}")
        
        self.changes_detected = changes
        
        if changes:
            self.logger.warning(f"Integrity check completed: {len(changes)} changes detected")
        else:
            self.logger.info("Integrity check completed: No changes detected")
            
        return changes
    
    def generate_report(self, output_file, format='text'):
        """Generate integrity check report"""
        if not self.changes_detected:
            self.logger.info("No changes to report")
            return
            
        try:
            with open(output_file, 'w') as f:
                if format.lower() == 'json':
                    json.dump(self.changes_detected, f, indent=2)
                else:
                    f.write("FILE INTEGRITY MONITOR REPORT\n")
                    f.write("=" * 40 + "\n\n")
                    f.write(f"Report generated: {datetime.now().isoformat()}\n")
                    f.write(f"Changes detected: {len(self.changes_detected)}\n\n")
                    
                    for change in self.changes_detected:
                        f.write(f"[{change['timestamp']}] {change['type']}: {change['file']}\n")
                    
            self.logger.info(f"Report generated: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")

class RealTimeHandler(FileSystemEventHandler):
    """Real-time file system event handler"""
    
    def __init__(self, fim):
        super().__init__()
        self.fim = fim
        
    def on_any_event(self, event):
        if not event.is_directory and self.fim.should_monitor_file(event.src_path):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] {event.event_type.upper()}: {event.src_path}")

def parse_patterns(pattern_string):
    """Parse comma-separated patterns"""
    if not pattern_string:
        return []
    return [p.strip() for p in pattern_string.split(',') if p.strip()]

def main():
    parser = argparse.ArgumentParser(
        description='File Integrity Monitor - Detect unauthorized file changes'
    )
    
    parser.add_argument('-d', '--directory', 
                        default=os.getcwd(),
                        help='Directory to monitor (default: current directory)')
    
    parser.add_argument('--hash', 
                        choices=['md5', 'sha1', 'sha256'],
                        default='sha256',
                        help='Hash algorithm (default: sha256)')
    
    parser.add_argument('-v', '--verbose', 
                        action='store_true',
                        help='Enable verbose logging')
    
    parser.add_argument('--baseline', 
                        default='fim_baseline.json',
                        help='Baseline file path')
    
    parser.add_argument('--include', 
                        help='File patterns to include (comma-separated)')
    
    parser.add_argument('--exclude', 
                        help='File patterns to exclude (comma-separated)')
    
    parser.add_argument('--create-baseline', 
                        action='store_true',
                        help='Create new baseline')
    
    parser.add_argument('--check', 
                        action='store_true',
                        help='Check integrity against baseline')
    
    parser.add_argument('--real-time', 
                        action='store_true',
                        help='Start real-time monitoring')
    
    parser.add_argument('-o', '--output', 
                        help='Output file for reports')
    
    parser.add_argument('--report-format', 
                        choices=['text', 'json'],
                        default='text',
                        help='Report format')
    
    args = parser.parse_args()
    
    # Parse patterns
    include_patterns = parse_patterns(args.include) or ['*']
    exclude_patterns = parse_patterns(args.exclude) or []
    
    # Initialize FIM
    fim = FileIntegrityMonitor(
        directories=args.directory,
        hash_algo=args.hash,
        baseline_file=args.baseline,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
        verbose=args.verbose
    )
    
    print("File Integrity Monitor v1.0")
    print("===========================")
    
    try:
        if args.create_baseline:
            if fim.create_baseline():
                print("\nBaseline created successfully!")
            else:
                print("\nError creating baseline.")
                sys.exit(1)
                
        elif args.check:
            if fim.load_baseline():
                changes = fim.check_integrity()
                if args.output:
                    fim.generate_report(args.output, args.report_format)
                    print(f"\nReport saved to: {args.output}")
            else:
                print("\nError loading baseline. Create baseline first.")
                sys.exit(1)
                
        elif args.real_time:
            if not WATCHDOG_AVAILABLE:
                print("\nReal-time monitoring requires 'watchdog' library.")
                print("Install with: pip install watchdog")
                sys.exit(1)
                
            print(f"Starting real-time monitoring of: {args.directory}")
            print("Press Ctrl+C to stop...\n")
            
            observer = Observer()
            observer.schedule(RealTimeHandler(fim), args.directory, recursive=True)
            observer.start()
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                observer.stop()
                print("\nReal-time monitoring stopped.")
            observer.join()
            
        else:
            # Default: single integrity check
            if fim.load_baseline():
                changes = fim.check_integrity()
                if args.output:
                    fim.generate_report(args.output, args.report_format)
                    print(f"\nReport saved to: {args.output}")
            else:
                print("\nNo baseline found. Use --create-baseline first.")
                
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
