#!/usr/bin/env python3
"""
Environment Variable Shamer - Because your secrets deserve public humiliation.
"""

import re
import sys
from pathlib import Path

# The naughty list of things that should NEVER be hardcoded
SUSPICIOUS_PATTERNS = [
    r'api[_-]?key\s*[:=]\s*["\'][\w\-]{10,}["\']',  # API keys
    r'password\s*[:=]\s*["\'][^"\']+["\']',  # Passwords
    r'secret\s*[:=]\s*["\'][^"\']+["\']',  # Secrets
    r'token\s*[:=]\s*["\'][\w\-]{10,}["\']',  # Tokens
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
    r'localhost|127\.0\.0\.1',  # Localhost references
    r'https?://[^/]+/api/',  # API endpoints
]

# Files we should probably ignore (unless you're REALLY naughty)
IGNORE_EXTENSIONS = {'.pyc', '.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip'}


def shame_file(filepath):
    """Publicly shame a file for its hardcoded sins."""
    try:
        content = filepath.read_text()
        shamed = False
        
        for i, line in enumerate(content.split('\n'), 1):
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    print(f"\033[91mSHAME! {filepath}:{i}\033[0m")
                    print(f"  {line.strip()[:100]}")
                    print(f"  \033[93m↑ This looks like it should be an environment variable!\033[0m\n")
                    shamed = True
                    break  # One shame per line is enough
        
        return shamed
    except Exception as e:
        print(f"Couldn't read {filepath}: {e}")
        return False


def main():
    """Main function - because even shame needs structure."""
    if len(sys.argv) < 2:
        print("Usage: python env_shamer.py <directory>")
        print("Example: python env_shamer.py .")
        sys.exit(1)
    
    target_dir = Path(sys.argv[1])
    if not target_dir.exists():
        print(f"Directory not found: {target_dir}")
        sys.exit(1)
    
    print("\033[94m🔍 Scanning for hardcoded secrets...\033[0m\n")
    
    total_shame = 0
    for filepath in target_dir.rglob('*'):
        if filepath.is_file() and filepath.suffix not in IGNORE_EXTENSIONS:
            if shame_file(filepath):
                total_shame += 1
    
    if total_shame == 0:
        print("\033[92m✅ No shame found! You're a responsible developer!\033[0m")
    else:
        print(f"\033[91m🔥 Found {total_shame} file(s) in need of environmental therapy!\033[0m")


if __name__ == "__main__":
    main()
