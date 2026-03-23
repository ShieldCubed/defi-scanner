const { hasSelector, analyzePatterns, SIGNATURES } = require("./analyzer");

function checkDonationAttack(bytecode) {
  const hasDeposit = hasSelector(bytecode, SIGNATURES.ERC4626_DEPOSIT);
  const hasBalanceOf = bytecode.includes("70a08231");
  const hasTotalAssets = bytecode.includes("01e1d114");
  if (hasDeposit && hasBalanceOf && hasTotalAssets) {
    return {
      rule: "DONATION_ATTACK",
      severity: "HIGH",
      description: "ERC4626 vault uses raw balanceOf for totalAssets(). Direct token transfers can break share/asset ratio.",
      pattern: "Challenge 1 - Unstoppable",
    };
  }
  return null;
}

function checkArbitraryCall(bytecode) {
  const hasFlashLoan = hasSelector(bytecode, SIGNATURES.FLASH_LOAN);
  const hasArbitraryCall = analyzePatterns(bytecode).includes("arbitrary_call");
  if (hasFlashLoan && hasArbitraryCall) {
    return {
      rule: "ARBITRARY_CALL",
      severity: "CRITICAL",
      description: "Flash loan function executes arbitrary external calls with user-supplied target and data.",
      pattern: "Challenge 3 - Truster",
    };
  }
  return null;
}

function checkAccountingMismatch(bytecode) {
  const patterns = analyzePatterns(bytecode);
  const hasMismatch = patterns.includes("balance_vs_storage");
  const hasFlashLoan = hasSelector(bytecode, SIGNATURES.FLASH_LOAN);
  if (hasMismatch && hasFlashLoan) {
    return {
      rule: "ACCOUNTING_MISMATCH",
      severity: "HIGH",
      description: "Flash loan pool checks address.balance but tracks deposits in mapping.",
      pattern: "Challenge 4 - Side Entrance",
    };
  }
  return null;
}

function checkOracleManipulation(bytecode) {
  const hasBalanceOf = bytecode.includes("70a08231");
  const hasExternalCall = bytecode.includes("fa");
  const hasTWAP = bytecode.includes("252587") ||
                  bytecode.includes("9d52a21") ||
                  bytecode.includes("50d25bcd");
  const hasV2Quote = bytecode.includes("ad615dec") ||
                     bytecode.includes("85f8c259");
  const isLendingContext =
    bytecode.includes("c55dae63") ||
    bytecode.includes("a415bcad") ||
    bytecode.includes("69328dec") ||
    bytecode.includes("e8eda9df");
  if (hasBalanceOf && hasExternalCall && !hasTWAP && isLendingContext) {
    return {
      rule: "ORACLE_MANIPULATION",
      severity: "CRITICAL",
      description: "Lending protocol calculates collateral using spot price without TWAP or Chainlink protection.",
      pattern: hasV2Quote ? "Challenge 6 - Puppet V2" : "Challenge 5 - Puppet V1",
    };
  }
  return null;
}

function checkMsgSenderSpoofing(bytecode) {
  const hasMulticall = hasSelector(bytecode, SIGNATURES.MULTICALL);
  const hasTailRead = bytecode.includes("6014") && bytecode.includes("03");
  if (hasMulticall && hasTailRead) {
    return {
      rule: "MSGSENDER_SPOOFING",
      severity: "HIGH",
      description: "Contract reads msg.sender from calldata tail when called by trusted forwarder.",
      pattern: "Challenge 2 - Naive Receiver",
    };
  }
  return null;
}

function checkPrivilegedEOA(bytecode) {
  const hasRole = bytecode.includes("91d14854");
  const hasMint = bytecode.includes("40c10f19");
  const hasTimelock = bytecode.includes("134008d3");
  const hasMultisig = bytecode.includes("ee52a2f3");
  if (hasRole && hasMint && !hasTimelock && !hasMultisig) {
    return {
      rule: "PRIVILEGED_SINGLE_EOA",
      severity: "CRITICAL",
      description: "Privileged role controls mint without multisig or timelock. Single point of failure - Resolv-style attack vector.",
      pattern: "Resolv hack 2026 - single EOA mint authority",
    };
  }
  return null;
}

function checkTwoStepMintFlow(bytecode) {
  const hasRequestMint = bytecode.includes("986d7a69");
  const hasCompleteMint = bytecode.includes("19b2a6b9");
  const hasRequestBurn = bytecode.includes("f67e6070");
  const hasCompleteBurn = bytecode.includes("a46e82d2");
  const hasServiceRole = bytecode.includes("a20e7d47");
  const hasRole = bytecode.includes("91d14854");
  const hasTwoStep = (hasRequestMint && hasCompleteMint) ||
                     (hasRequestBurn && hasCompleteBurn);
  if (hasTwoStep && hasServiceRole && hasRole) {
    return {
      rule: "UNCHECKED_TWO_STEP_MINT",
      severity: "CRITICAL",
      description: "Two-step mint/burn flow with SERVICE_ROLE. No amount validation between request and completion - Resolv-style 400x over-mint possible.",
      pattern: "Resolv hack 2026 - requestMint/completeMint without on-chain validation",
    };
  }
  return null;
}

function checkUnboundedMint(bytecode) {
  const hasMint = bytecode.includes("40c10f19");
  const hasCap = bytecode.includes("355274ea") ||
                 bytecode.includes("239c70ae");
  const hasRole = bytecode.includes("91d14854");
  const hasExternalMintControl = bytecode.includes("7a9a6f72") ||
                                  bytecode.includes("ea2f18b7");
  // Only flag stablecoin/synthetic minting with role control and no cap
  // Not DEX LP token minting which is expected
  if (hasMint && !hasCap && hasRole && hasExternalMintControl) {
    return {
      rule: "UNBOUNDED_MINT",
      severity: "CRITICAL",
      description: "Privileged mint with no cap and two-step flow. Resolv-style 400x over-mint possible.",
      pattern: "Resolv hack 2026 - unbounded mint vulnerability",
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
    checkPrivilegedEOA,
    checkTwoStepMintFlow,
    checkUnboundedMint,
  ];
  return checks.map(check => check(bytecode)).filter(Boolean);
}

module.exports = { runAllRules };
