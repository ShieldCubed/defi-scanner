#!/usr/bin/env python3
"""
State Space Mapper — extracts state variables, functions, and transitions
from Solidity source code to build a directed state graph.
"""
import re
import json
import sys
from pathlib import Path

def extract_state_variables(source):
    """Extract state variables and their types."""
    state_vars = []
    # Match state variable declarations (not inside functions)
    patterns = [
        r'(?:uint256|uint|int256|int|address|bool|bytes32|bytes|string|mapping[^;]+)\s+(?:public|private|internal|)?\s*(\w+)\s*;',
        r'(?:uint256|uint|int256|int|address|bool|bytes32)\s+(?:public|private|internal|constant|immutable)?\s*(\w+)\s*[=;]',
    ]
    for pattern in patterns:
        matches = re.findall(pattern, source)
        state_vars.extend(matches)
    return list(set(state_vars))

def extract_functions(source):
    """Extract functions with their modifiers and state-modifying operations."""
    functions = []
    # Match function signatures
    fn_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*((?:public|private|internal|external|view|pure|payable|override|virtual|\s)*)\{'
    matches = re.finditer(fn_pattern, source, re.MULTILINE)
    
    for match in matches:
        fn_name = match.group(1)
        params = match.group(2)
        modifiers = match.group(3).strip()
        
        # Get function body (rough extraction)
        start = match.end()
        depth = 1
        i = start
        while i < len(source) and depth > 0:
            if source[i] == '{': depth += 1
            elif source[i] == '}': depth -= 1
            i += 1
        body = source[start:i-1]
        
        # Extract what state vars this function reads/writes
        reads = []
        writes = []
        requires = []
        emits = []
        external_calls = []
        
        # Find require/assert statements (invariants)
        req_pattern = r'require\s*\(([^)]+)\)'
        requires = re.findall(req_pattern, body)
        
        # Find emit statements
        emit_pattern = r'emit\s+(\w+)\s*\('
        emits = re.findall(emit_pattern, body)
        
        # Find external calls (reentrancy surface)
        ext_pattern = r'(\w+)\.(\w+)\s*\{'
        external_calls = re.findall(ext_pattern, body)
        
        # Detect state modifications (assignments)
        assign_pattern = r'(\w+)\s*(?:\+=|-=|\*=|\/=|=)\s*'
        writes = re.findall(assign_pattern, body)
        
        is_view = 'view' in modifiers or 'pure' in modifiers
        is_payable = 'payable' in modifiers
        is_external = 'external' in modifiers or 'public' in modifiers
        
        functions.append({
            'name': fn_name,
            'params': params,
            'modifiers': modifiers,
            'is_view': is_view,
            'is_payable': is_payable,
            'is_external': is_external,
            'requires': requires,
            'emits': emits,
            'external_calls': external_calls,
            'state_writes': list(set(writes)),
            'body_preview': body[:200].replace('\n', ' ').strip()
        })
    
    return functions

def build_state_graph(functions, state_vars):
    """Build directed graph of state transitions."""
    graph = {
        'nodes': [],
        'edges': [],
        'entry_points': [],
        'state_variables': state_vars
    }
    
    # Each function is a node
    for fn in functions:
        node = {
            'id': fn['name'],
            'type': 'function',
            'is_external': fn['is_external'],
            'is_view': fn['is_view'],
            'modifies_state': len(fn['state_writes']) > 0,
            'has_requires': len(fn['requires']) > 0,
            'has_external_calls': len(fn['external_calls']) > 0,
            'requires': fn['requires'],
            'state_writes': fn['state_writes'],
            'emits': fn['emits']
        }
        graph['nodes'].append(node)
        
        if fn['is_external'] and not fn['is_view']:
            graph['entry_points'].append(fn['name'])
    
    # Build edges based on external calls between functions
    for fn in functions:
        for call in fn['external_calls']:
            graph['edges'].append({
                'from': fn['name'],
                'to': f"{call[0]}.{call[1]}",
                'type': 'external_call'
            })
    
    return graph

def analyze_file(sol_file):
    """Main analysis function."""
    source = Path(sol_file).read_text(encoding='utf-8', errors='ignore')
    
    print(f"[*] Analyzing: {sol_file}")
    print(f"[*] Source size: {len(source)} chars")
    
    state_vars = extract_state_variables(source)
    print(f"[*] State variables found: {len(state_vars)}")
    
    functions = extract_functions(source)
    print(f"[*] Functions found: {len(functions)}")
    
    graph = build_state_graph(functions, state_vars)
    print(f"[*] Entry points: {graph['entry_points']}")
    
    return {
        'file': sol_file,
        'state_variables': state_vars,
        'functions': functions,
        'graph': graph
    }

if __name__ == '__main__':
    sol_file = sys.argv[1] if len(sys.argv) > 1 else '/home/asus/ScanIT/pentagi/data/flow-1/rusd_contracts/source/RUSD_complete.sol'
    result = analyze_file(sol_file)
    
    out_file = sys.argv[2] if len(sys.argv) > 2 else '/tmp/state_map.json'
    with open(out_file, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\n[✓] State map saved to {out_file}")
    print(f"[✓] Functions: {[f['name'] for f in result['functions']]}")
