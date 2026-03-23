require("dotenv").config();
const { ethers } = require("ethers");
const { runAllRules } = require("./src/rules");
const { analyzeWithSlither } = require("./src/slither");
const { printHeader, printTarget, printFinding, printSummary } = require("./src/report");

const RPC = `https://eth-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_KEY}`;

const TARGETS = [
  { name: "Resolv USR Counter (EXPLOITED)", address: "0xAC85eF29192487E0a109b7f9E40C267a9ea95f2e", tvl: 25e6, category: "Stablecoin" },
  { name: "Aave V3 Pool", address: "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", tvl: 8e9, category: "Lending" },
  { name: "Compound V3 USDC", address: "0xc3d688B66703497DAA19211EEdff47f25384cdc3", tvl: 1.3e9, category: "Lending" },
  { name: "MakerDAO Vat", address: "0x35D1b3F3D7966A1DFe207aa4514C12a259A0492B", tvl: 7e9, category: "CDP" },
  { name: "Uniswap V3 Factory", address: "0x1F98431c8aD98523631AE4a59f267346ea31F984", tvl: 1.7e9, category: "DEX" },
  { name: "Uniswap V2 Factory", address: "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", tvl: 5e8, category: "DEX" },
  { name: "Curve 3pool", address: "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7", tvl: 1.8e9, category: "DEX" },
  { name: "Balancer Vault", address: "0xBA12222222228d8Ba445958a75a0704d566BF2C8", tvl: 1.2e9, category: "DEX" },
  { name: "Convex Booster", address: "0xF403C135812408BFbE8713b5A23a04b3D48AAE31", tvl: 2e9, category: "Yield" },
  { name: "Frax ETH Minter", address: "0xbAFA44EFE7901E04E39Dad13167D089C559c1138", tvl: 8e8, category: "Liquid Staking" },
  { name: "Rocket Pool", address: "0xDD3f50F8A6CafbE9b31a427582963f465E745AF8", tvl: 3e9, category: "Liquid Staking" },
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
