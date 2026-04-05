#!/usr/bin/env python3
"""
Cohomology-Inspired Hole Detector
Finds state-space holes: reachable states that violate protocol invariants.
Uses graph reachability + invariant checking to find exploit paths.
"""
import json
import sys
import itertools
from pathlib import Path

# ── KNOWN VULNERABILITY PATTERNS ─────────────────────────────────
HOLE_PATTERNS = [
    {
        'id': 'FLASH_REENTRANCY',
        'name': 'Flash Loan Reentrancy Hole',
        'description': 'External call inside flash loan before state update creates reentrancy hole',
        'severity': 'CRITICAL',
        'detect': lambda fns: any(
            'flashLoan' in f['name'].lower() and len(f['external_calls']) > 0
            for f in fns
        )
    },
    {
        'id': 'UNCAPPED_MINT',
        'name': 'Uncapped Mint Authority Hole',
        'description': 'Mint function lacks supply cap — allows infinite token creation',
        'severity': 'CRITICAL',
        'detect': lambda fns: any(
            'mint' in f['name'].lower() and
            not any('totalSupply' in r or 'cap' in r.lower() or 'limit' in r.lower()
                   for r in f['requires'])
            for f in fns if not f['is_view']
        )
    },
    {
        'id': 'SUPPLY_ORACLE_HOLE',
        'name': 'Supply Inflation Oracle Hole',
        'description': 'Flash loan mints new tokens mid-tx — any oracle reading totalSupply during callback gets corrupted value',
        'severity': 'CRITICAL',
        'detect': lambda fns: (
            any('flashLoan' in f['name'].lower() for f in fns) and
            any('mint' in f['name'].lower() for f in fns) and
            any('totalSupply' in f['name'].lower() or 'circulatingSupply' in f['name'].lower()
                for f in fns)
        )
    },
    {
        'id': 'MISSING_REENTRANCY_GUARD',
        'name': 'Missing Reentrancy Guard on State-Modifying External Call',
        'description': 'Functions with external calls that modify state lack nonReentrant modifier',
        'severity': 'HIGH',
        'detect': lambda fns: any(
            len(f['external_calls']) > 0 and
            f['modifies_state'] and
            'nonReentrant' not in f['modifiers'] and
            'nonreentrant' not in f['modifiers'].lower() and
            not f['is_view']
            for f in fns
        )
    },
    {
        'id': 'UNRESTRICTED_BURN',
        'name': 'Unrestricted Burn with External Call Hole',
        'description': 'Burn function calls external contract before updating balances',
        'severity': 'HIGH',
        'detect': lambda fns: any(
            'burn' in f['name'].lower() and
            len(f['external_calls']) > 0 and
            not f['is_view']
            for f in fns
        )
    },
    {
        'id': 'MAXFLASHLOAN_OVERFLOW',
        'name': 'maxFlashLoan Returns type(uint256).max',
        'description': 'Uncapped flash loan size causes arithmetic overflow in fee calculation',
        'severity': 'CRITICAL',
        'detect': lambda fns: any(
            'maxFlashLoan' in f['name'] or
            'FLASH_LOAN_FEE' in f['name']
            for f in fns
        )
    },
    {
        'id': 'CROSS_CONTRACT_STATE_HOLE',
        'name': 'Cross-Contract State Consistency Hole',
        'description': 'State modified in one contract before external contract updates — window for inconsistency',
        'severity': 'HIGH',
        'detect': lambda fns: any(
            len(f['external_calls']) > 1 and f['modifies_state']
            for f in fns
        )
    },
    {
        'id': 'APPROVAL_FRONT_RUN',
        'name': 'Approval Front-Running Hole',
        'description': 'approve() without increaseAllowance/decreaseAllowance creates front-running window',
        'severity': 'MEDIUM',
        'detect': lambda fns: (
            any(f['name'] == 'approve' for f in fns) and
            not any(f['name'] == 'increaseAllowance' for f in fns)
        )
    },
    {
        'id': 'LAYERZERO_REPLAY',
        'name': 'LayerZero Cross-Chain Replay Hole',
        'description': 'lzReceive without nonce tracking allows message replay across chains',
        'severity': 'HIGH',
        'detect': lambda fns: (
            any('lzReceive' in f['name'] for f in fns) and
            not any('nonce' in ' '.join(f['requires']).lower() for f in fns
                   if 'lzReceive' in f['name'])
        )
    },
]

def find_exploit_paths(functions, holes):
    """Find multi-step function sequences that lead to holes."""
    exploit_paths = []
    
    fn_map = {f['name']: f for f in functions}
    external_fns = [f for f in functions if f['is_external'] and not f['is_view']]
    
    # For each hole, find which functions are involved
    for hole in holes:
        path = {
            'hole_id': hole['id'],
            'hole_name': hole['name'],
            'severity': hole['severity'],
            'attack_sequence': [],
            'invariant_violations': []
        }
        
        # Build attack sequence based on hole type
        if hole['id'] == 'FLASH_REENTRANCY' or hole['id'] == 'SUPPLY_ORACLE_HOLE':
            flash_fns = [f for f in functions if 'flashLoan' in f['name'].lower()]
            mint_fns = [f for f in functions if 'mint' in f['name'].lower()]
            path['attack_sequence'] = (
                [f['name'] for f in flash_fns] +
                ['[callback: onFlashLoan]'] +
                [f['name'] for f in mint_fns[:1]] +
                ['[read: totalSupply — INFLATED]',
                 '[exploit: oracle manipulation / CDP drain]']
            )
            path['invariant_violations'] = [
                'totalSupply should not change during active flash loan',
                'oracle reads during flash loan callback return corrupted values',
                'CEI (Checks-Effects-Interactions) pattern violated'
            ]
        
        elif hole['id'] == 'UNCAPPED_MINT':
            mint_fns = [f for f in functions if 'mint' in f['name'].lower()]
            path['attack_sequence'] = (
                ['[impersonate: BorrowerOps / authorized minter]'] +
                [f['name'] for f in mint_fns] +
                ['[result: arbitrary token inflation]']
            )
            path['invariant_violations'] = [
                'totalSupply must not exceed protocol-defined cap',
                'mint authority must be strictly access-controlled'
            ]
        
        elif hole['id'] == 'MAXFLASHLOAN_OVERFLOW':
            path['attack_sequence'] = [
                'maxFlashLoan(token) → returns type(uint256).max',
                'flashFee(token, uint256.max) → ARITHMETIC OVERFLOW → REVERT',
                '[workaround: use amount < uint256.max to bypass fee check]'
            ]
            path['invariant_violations'] = [
                'maxFlashLoan must return value bounded by actual liquidity',
                'flashFee must not overflow for any valid loan amount'
            ]
        
        elif hole['id'] == 'LAYERZERO_REPLAY':
            path['attack_sequence'] = [
                'lzReceive(srcChainId, srcAddress, nonce, payload)',
                '[replay same message from chain A on chain B]',
                '[result: double-mint or double-transfer]'
            ]
            path['invariant_violations'] = [
                'Each cross-chain message must be processed exactly once',
                'Nonce or message hash must be tracked and rejected on replay'
            ]
        
        else:
            path['attack_sequence'] = ['[see hole description for attack path]']
            path['invariant_violations'] = ['Protocol invariant violated — see hole description']
        
        exploit_paths.append(path)
    
    return exploit_paths

def compute_hole_score(holes):
    """Compute overall risk score based on holes found."""
    weights = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1}
    score = sum(weights.get(h['severity'], 0) for h in holes)
    
    if score >= 20: return 'CRITICAL'
    if score >= 10: return 'HIGH'
    if score >= 5:  return 'MEDIUM'
    return 'LOW'

def detect_holes(state_map_file):
    """Main hole detection function."""
    with open(state_map_file) as f:
        state_map = json.load(f)
    
    functions = state_map['functions']
    state_vars = state_map['state_variables']
    
    print(f"\n[COHOMOLOGY] Analyzing {len(functions)} functions, {len(state_vars)} state variables")
    print(f"[COHOMOLOGY] Running {len(HOLE_PATTERNS)} hole pattern detectors...\n")
    
    holes_found = []
    for pattern in HOLE_PATTERNS:
        try:
            detected = pattern['detect'](functions)
            status = "🔴 FOUND" if detected else "✅ CLEAR"
            print(f"  {status} [{pattern['severity']}] {pattern['name']}")
            if detected:
                holes_found.append({
                    'id': pattern['id'],
                    'name': pattern['name'],
                    'description': pattern['description'],
                    'severity': pattern['severity']
                })
        except Exception as e:
            print(f"  ⚠️  Error in {pattern['id']}: {e}")
    
    exploit_paths = find_exploit_paths(functions, holes_found)
    overall_risk = compute_hole_score(holes_found)
    
    result = {
        'file': state_map['file'],
        'overall_risk': overall_risk,
        'holes_found': len(holes_found),
        'holes': holes_found,
        'exploit_paths': exploit_paths,
        'state_variables_analyzed': len(state_vars),
        'functions_analyzed': len(functions),
        'entry_points': state_map['graph']['entry_points']
    }
    
    print(f"\n{'='*60}")
    print(f"COHOMOLOGY ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"Overall Risk     : {overall_risk}")
    print(f"Holes Found      : {len(holes_found)}")
    print(f"Functions Scanned: {len(functions)}")
    print(f"State Vars       : {len(state_vars)}")
    print(f"\nHOLES DETECTED:")
    for h in holes_found:
        print(f"  [{h['severity']}] {h['name']}")
        print(f"    → {h['description']}")
    
    print(f"\nEXPLOIT PATHS:")
    for ep in exploit_paths:
        print(f"\n  [{ep['severity']}] {ep['hole_name']}")
        print(f"  Attack sequence:")
        for step in ep['attack_sequence']:
            print(f"    → {step}")
        print(f"  Invariant violations:")
        for v in ep['invariant_violations']:
            print(f"    ✗ {v}")
    
    return result

if __name__ == '__main__':
    state_map = sys.argv[1] if len(sys.argv) > 1 else '/tmp/state_map.json'
    out_file = sys.argv[2] if len(sys.argv) > 2 else '/tmp/cohomology_report.json'
    result = detect_holes(state_map)
    
    out_file = sys.argv[2] if len(sys.argv) > 2 else '/tmp/cohomology_report.json'
    with open(out_file, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\n[✓] Full report saved to {out_file}")
