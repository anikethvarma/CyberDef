#!/usr/bin/env python3
"""
Fix Python 3.9 compatibility by replacing union type syntax.
Converts 'type | None' to 'Optional[type]' for Python 3.9 compatibility.
"""

import re
from pathlib import Path

def fix_union_types(file_path):
    """Fix union type syntax in a Python file."""
    print(f"Processing {file_path}...")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Add Optional import if not present
    if 'Optional[' in content:
        if not re.search(r'from typing import .*?\bOptional\b', content):
            if 'from typing import' in content:
                # Handle from typing import (A, B)
                if re.search(r'from typing import \([^)]+\)', content):
                    content = re.sub(
                        r'from typing import \(([^)]+)\)',
                        r'from typing import (\1, Optional)',
                        content
                    )
                else:
                    # Handle from typing import A, B
                    content = re.sub(
                        r'from typing import ([^\n]+)',
                        r'from typing import \1, Optional',
                        content
                    )
            else:
                # Add import line if none exists
                content = "from typing import Optional\n" + content
    
    # Replace union types with Optional
    # Pattern: type | None = value
    content = re.sub(r'(\w+)\s*\|\s*None(\s*=)', r'Optional[\1]\2', content)
    
    # Pattern: list[type] | None = value  
    content = re.sub(r'(list\[[^\]]+\])\s*\|\s*None(\s*=)', r'Optional[\1]\2', content)
    
    # Pattern: dict[type, type] | None = value
    content = re.sub(r'(dict\[[^\]]+\])\s*\|\s*None(\s*=)', r'Optional[\1]\2', content)
    
    if content != original_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"  ✓ Fixed union types in {file_path}")
        return True
    else:
        print(f"  - No changes needed in {file_path}")
        return False

def main():
    """Fix Python 3.9 compatibility in shared models."""
    print("Fixing Python 3.9 compatibility...")
    
    # Scans for all files in specified directories
    directories = ['shared_models', 'rules_engine', 'rollups', 'raw_storage', 'log_parser']
    
    fixed_count = 0
    for directory in directories:
        dir_path = Path(directory)
        if dir_path.exists():
            for path in dir_path.glob('*.py'):
                if fix_union_types(path):
                    fixed_count += 1
    
    # Also fix main.py
    if Path('main.py').exists():
        if fix_union_types(Path('main.py')):
            fixed_count += 1
    
    print(f"\nFixed {fixed_count} files for Python 3.9 compatibility")
    
    # Test import after fixes
    print("\nTesting imports...")
    try:
        from shared_models.events import ParsedEvent, RawEventRow
        print("✓ shared_models.events imports successfully")
        
        from log_parser.syslog_parser import SyslogApacheParser
        print("✓ log_parser.syslog_parser imports successfully")
        
        print("✓ All imports work with Python 3.9!")
        
    except Exception as e:
        print(f"✗ Import test failed: {e}")

if __name__ == "__main__":
    main()