require("dotenv").config();
const { ethers } = require("ethers");
const { runAllRules } = require("./src/rules");
const { analyzeWithSlither } = require("./src/slither");
const { printHeader, printTarget, printFinding, printSummary } = require("./src/report");

const RPC = `https://eth-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_KEY}`;

const TARGETS = [
  { name: "Uniswap V3 Factory", address: "0x1F98431c8aD98523631AE4a59f267346ea31F984", tvl: 1.7e9, category: "DEX" },
  { name: "Uniswap V2 Factory", address: "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", tvl: 5e8, category: "DEX" },
  { name: "Compound USDC", address: "0x39AA39c021dfbaE8faC545936693aC917d5E7563", tvl: 1e9, category: "Lending" },
  { name: "Curve 3pool", address: "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7", tvl: 1.8e9, category: "DEX" },
  { name: "Convex Booster", address: "0xF403C135812408BFbE8713b5A23a04b3D48AAE31", tvl: 2e9, category: "Yield" },
];

async function scan() {
  printHeader();
  const provider = new ethers.JsonRpcProvider(RPC);
  const results = [];

  console.log(`Scanning ${TARGETS.length} known DeFi contracts...\n`);

  for (const target of TARGETS) {
    try {
      const bytecode = await provider.getCode(target.address);
      if (bytecode === "0x") continue;

      // Layer 1: bytecode pattern matching (fast)
      const bytecodeFindings = runAllRules(bytecode);

      // Layer 2: Slither static analysis (slower but deeper)
      const slitherFindings = await analyzeWithSlither(target.address);

      const findings = [...bytecodeFindings, ...slitherFindings];

      if (findings.length > 0) {
        printTarget(target);
        findings.forEach(printFinding);
        results.push({ ...target, findings });
      } else {
        console.log(`✓ ${target.name} — no issues detected`);
      }
    } catch (e) {
      console.log(`✗ ${target.name} — ${e.message}`);
    }
  }

  printSummary(results);
}

scan().catch(console.error);
