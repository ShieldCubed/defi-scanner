const { hasSelector, analyzePatterns, SIGNATURES } = require("./analyzer");

// Rule 1: Donation Attack (Unstoppable)
// ERC4626 vault where totalAssets() reads raw balanceOf
function checkDonationAttack(bytecode) {
  const hasDeposit = hasSelector(bytecode, SIGNATURES.ERC4626_DEPOSIT);
  const hasBalanceOf = bytecode.includes("70a08231");
  const hasTotalAssets = bytecode.includes("01e1d114");

  if (hasDeposit && hasBalanceOf && hasTotalAssets) {
    return {
      rule: "DONATION_ATTACK",
      severity: "HIGH",
      description: "ERC4626 vault uses raw balanceOf for totalAssets(). Direct token transfers can break share/asset ratio.",
      pattern: "Challenge 1 — Unstoppable",
    };
  }
  return null;
}

// Rule 2: Arbitrary External Call (Truster)
// flashLoan accepts user-controlled target + calldata
function checkArbitraryCall(bytecode) {
  const hasFlashLoan = hasSelector(bytecode, SIGNATURES.FLASH_LOAN);
  const hasArbitraryCall = analyzePatterns(bytecode).includes("arbitrary_call");

  if (hasFlashLoan && hasArbitraryCall) {
    return {
      rule: "ARBITRARY_CALL",
      severity: "CRITICAL",
      description: "Flash loan function executes arbitrary external calls with user-supplied target and data.",
      pattern: "Challenge 3 — Truster",
    };
  }
  return null;
}

// Rule 3: Balance vs Storage Mismatch (Side Entrance)
// Pool tracks balances in mapping but checks address(this).balance
function checkAccountingMismatch(bytecode) {
  const patterns = analyzePatterns(bytecode);
  const hasMismatch = patterns.includes("balance_vs_storage");
  const hasFlashLoan = hasSelector(bytecode, SIGNATURES.FLASH_LOAN);

  if (hasMismatch && hasFlashLoan) {
    return {
      rule: "ACCOUNTING_MISMATCH",
      severity: "HIGH",
      description: "Flash loan pool checks address.balance but tracks deposits in mapping. Re-entrant deposit can satisfy repayment check.",
      pattern: "Challenge 4 — Side Entrance",
    };
  }
  return null;
}

// Rule 4: Spot Price Oracle (Puppet)
// Lending pool uses Uniswap spot price as collateral oracle

function checkOracleManipulation(bytecode) {
  const hasBalanceOf = bytecode.includes("70a08231");
  const hasExternalCall = bytecode.includes("fa");
  const hasTWAP = bytecode.includes("252587") ||
                  bytecode.includes("9d52a21") ||
                  bytecode.includes("50d25bcd");

  // Only flag lending/CDP contracts — DEX contracts legitimately read balances
  const isLendingContext = 
    bytecode.includes("c55dae63") || // borrow()
    bytecode.includes("a415bcad") || // borrow(address,uint256,uint256,uint16,address)
    bytecode.includes("69328dec") || // withdraw(address,uint256,address)
    bytecode.includes("e8eda9df") || // deposit(address,uint256,address,uint16)
    bytecode.includes("liquidat");   // any liquidation function

  if (hasBalanceOf && hasExternalCall && !hasTWAP && isLendingContext) {
    return {
      rule: "ORACLE_MANIPULATION",
      severity: "CRITICAL",
      description: "Lending protocol calculates collateral using spot price without TWAP or Chainlink protection.",
      pattern: "Challenge 5 — Puppet",
    };
  }
  return null;
}

// Rule 5: msgSender Spoofing (Naive Receiver)
// Trusted forwarder reads msg.sender from calldata tail
function checkMsgSenderSpoofing(bytecode) {
  const hasMulticall = hasSelector(bytecode, SIGNATURES.MULTICALL);
  // CALLDATASIZE - 20 pattern (reading last 20 bytes as address)
  const hasTailRead = bytecode.includes("6014") && bytecode.includes("03");

  if (hasMulticall && hasTailRead) {
    return {
      rule: "MSGSENDER_SPOOFING",
      severity: "HIGH",
      description: "Contract reads msg.sender from calldata tail when called by trusted forwarder. Attacker can append any address to spoof identity.",
      pattern: "Challenge 2 — Naive Receiver",
    };
  }
  return null;
}

function runAllRules(bytecode) {
  const checks = [
    checkDonationAttack,
    checkArbitraryCall,
    checkAccountingMismatch,
    checkOracleManipulation,
    checkMsgSenderSpoofing,
  ];

  return checks
    .map(check => check(bytecode))
    .filter(Boolean);
}

module.exports = { runAllRules };
