#!/usr/bin/env python3
"""
Script to process vulnerability analysis results and create consolidated CSV
"""

import json
import xml.etree.ElementTree as ET
import csv
import re
from collections import defaultdict
import os

# Top 25 CWE categories from 2024
TOP_25_CWE = {
    20, 79, 89, 190, 269, 287, 352, 362, 416, 476, 22, 78, 77, 119, 798, 
    125, 276, 918, 306, 863, 434, 285, 94, 295, 732
}

def parse_cppcheck_xml(filepath):
    """Parse cppcheck XML results"""
    results = []
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        
        for error in root.findall('.//error'):
            cwe_id = error.get('cwe')
            if cwe_id:
                cwe_num = int(cwe_id)
                results.append({
                    'cwe_id': cwe_num,
                    'file': error.find('location').get('file') if error.find('location') is not None else 'unknown',
                    'line': error.find('location').get('line') if error.find('location') is not None else 'unknown'
                })
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
    
    return results

def parse_flawfinder_txt(filepath):
    """Parse flawfinder text results"""
    results = []
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            
        # Find CWE patterns like (CWE-123) or (CWE-123, CWE-456)
        cwe_pattern = r'CWE-(\d+)'
        matches = re.findall(cwe_pattern, content)
        
        # Also extract file information
        lines = content.split('\n')
        current_file = None
        for line in lines:
            if line.strip().startswith('./') or 'Examining' in line:
                # Extract filename
                if 'Examining' in line:
                    current_file = line.split('Examining ')[1] if 'Examining ' in line else None
            elif 'CWE-' in line:
                cwe_ids = re.findall(cwe_pattern, line)
                for cwe_id in cwe_ids:
                    results.append({
                        'cwe_id': int(cwe_id),
                        'file': current_file or 'unknown',
                        'line': 'unknown'
                    })
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
    
    return results

def parse_semgrep_json(filepath):
    """Parse semgrep JSON results"""
    results = []
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        for result in data.get('results', []):
            # Check if CWE information is available
            metadata = result.get('extra', {}).get('metadata', {})
            cwe_info = metadata.get('cwe', [])
            
            if cwe_info:
                for cwe in cwe_info:
                    if isinstance(cwe, str):
                        # CWE format can be "CWE-78: Description" or just "CWE-78"
                        cwe_match = re.search(r'CWE-(\d+)', cwe)
                        if cwe_match:
                            cwe_num = int(cwe_match.group(1))
                            results.append({
                                'cwe_id': cwe_num,
                                'file': result.get('path', 'unknown'),
                                'line': result.get('start', {}).get('line', 'unknown')
                            })
            else:
                # Check rule ID for CWE information
                rule_id = result.get('check_id', '')
                if 'cwe' in rule_id.lower():
                    # Try to extract CWE from rule ID
                    cwe_match = re.search(r'cwe-?(\d+)', rule_id.lower())
                    if cwe_match:
                        cwe_num = int(cwe_match.group(1))
                        results.append({
                            'cwe_id': cwe_num,
                            'file': result.get('path', 'unknown'),
                            'line': result.get('start', {}).get('line', 'unknown')
                        })
                    else:
                        # For findings without explicit CWE, assign a generic security issue
                        results.append({
                            'cwe_id': 691,  # Generic "Insufficient Control Flow Management"
                            'file': result.get('path', 'unknown'),
                            'line': result.get('start', {}).get('line', 'unknown')
                        })
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
    
    return results

def count_findings_by_cwe(results):
    """Count findings by CWE ID"""
    cwe_counts = defaultdict(int)
    for result in results:
        cwe_counts[result['cwe_id']] += 1
    return dict(cwe_counts)

def create_consolidated_csv():
    """Create consolidated CSV file"""
    projects = ['brpc', 'caffe', 'terminal']
    tools = {
        'cppcheck': lambda p: f'cppcheck_results/{p}_cppcheck.xml',
        'flawfinder': lambda p: f'flawfinder_results/{p}_flawfinder.txt',
        'semgrep': lambda p: f'semgrep_results/{p}_semgrep.json'
    }
    
    csv_data = []
    
    for project in projects:
        print(f"Processing project: {project}")
        
        for tool_name, get_filepath in tools.items():
            filepath = get_filepath(project)
            print(f"  Processing {tool_name}: {filepath}")
            
            if not os.path.exists(filepath):
                print(f"    File not found: {filepath}")
                continue
            
            # Parse results based on tool type
            if tool_name == 'cppcheck':
                results = parse_cppcheck_xml(filepath)
            elif tool_name == 'flawfinder':
                results = parse_flawfinder_txt(filepath)
            elif tool_name == 'semgrep':
                results = parse_semgrep_json(filepath)
            else:
                continue
            
            # Count findings by CWE
            cwe_counts = count_findings_by_cwe(results)
            print(f"    Found {len(cwe_counts)} unique CWEs with {sum(cwe_counts.values())} total findings")
            
            # Add to CSV data
            for cwe_id, count in cwe_counts.items():
                is_top_25 = 'Yes' if cwe_id in TOP_25_CWE else 'No'
                csv_data.append({
                    'Project_name': project,
                    'Tool_name': tool_name,
                    'CWE_ID': cwe_id,
                    'Number_of_Findings': count,
                    'Is_In_CWE_Top_25': is_top_25
                })
    
    # Write to CSV
    output_file = 'consolidated_vulnerability_results.csv'
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['Project_name', 'Tool_name', 'CWE_ID', 'Number_of_Findings', 'Is_In_CWE_Top_25']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in csv_data:
            writer.writerow(row)
    
    print(f"\nConsolidated results saved to: {output_file}")
    print(f"Total rows: {len(csv_data)}")
    
    return output_file

if __name__ == "__main__":
    create_consolidated_csv()
