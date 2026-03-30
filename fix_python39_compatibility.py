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
    if 'from typing import' in content and 'Optional' not in content:
        content = re.sub(
            r'from typing import ([^)]+)',
            r'from typing import \1, Optional',
            content
        )
    
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
    
    # Files to fix
    files_to_fix = [
        'shared_models/events.py',
        'shared_models/files.py', 
        'shared_models/incidents.py',
        'shared_models/chunks.py',
        'shared_models/agents.py'
    ]
    
    fixed_count = 0
    for file_path in files_to_fix:
        path = Path(file_path)
        if path.exists():
            if fix_union_types(path):
                fixed_count += 1
        else:
            print(f"  ! File not found: {file_path}")
    
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