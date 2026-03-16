const { ethers } = require("ethers");

const ALCHEMY_KEY = process.env.ALCHEMY_KEY;
const RPC = `https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}`;

// Known vulnerable bytecode signatures
const SIGNATURES = {
  // ERC4626 deposit function selector
  ERC4626_DEPOSIT: "0x6e553f65",
  // flashLoan with arbitrary target (Truster pattern)
  FLASH_LOAN: "0x5cffe9de",
  // Uniswap V1 pair balance call (oracle pattern)
  UNISWAP_V1_BALANCE: "0x70a08231",
  // multicall selector
  MULTICALL: "0xac9650d8",
  // transferFrom selector
  TRANSFER_FROM: "0x23b872dd",
};

// Check if bytecode contains a function selector
function hasSelector(bytecode, selector) {
  return bytecode.toLowerCase().includes(selector.slice(2).toLowerCase());
}

// Check for dangerous patterns in bytecode
function analyzePatterns(bytecode) {
  const patterns = [];

  // CALL opcode after CALLDATALOAD — arbitrary external call pattern
  if (bytecode.includes("f1") && bytecode.includes("35")) {
    patterns.push("arbitrary_call");
  }

  // SELFBALANCE vs storage balance mismatch pattern
  if (bytecode.includes("47") && bytecode.includes("54")) {
    patterns.push("balance_vs_storage");
  }

  // STATICCALL to external address for pricing
  if (bytecode.includes("fa") && bytecode.includes("70a08231")) {
    patterns.push("external_price_feed");
  }

  return patterns;
}

async function getTokenBalances(address, tokens) {
  const provider = new ethers.JsonRpcProvider(RPC);
  const ERC20_ABI = ["function balanceOf(address) view returns (uint256)"];
  const balances = {};

  for (const token of tokens) {
    try {
      const contract = new ethers.Contract(token.address, ERC20_ABI, provider);
      const balance = await contract.balanceOf(address);
      balances[token.symbol] = {
        raw: balance.toString(),
        formatted: ethers.formatUnits(balance, token.decimals),
      };
    } catch (e) {
      balances[token.symbol] = null;
    }
  }

  return balances;
}

module.exports = { hasSelector, analyzePatterns, getTokenBalances, SIGNATURES };
