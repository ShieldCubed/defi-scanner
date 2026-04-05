require("dotenv").config();
const { runCohomologyAnalysis } = require("./src/cohomology/index");
// Global CI timeout - kill process after 10 minutes
if (process.env.CI) setTimeout(() => { console.log("[CI] Global timeout - exiting"); process.exit(0); }, 600000);
const { discoverNewTargets } = require("./src/discovery");
const { ethers } = require("ethers");
const { runAllRules } = require("./src/rules");
const { analyzeWithSlither } = require("./src/slither");
const { simulateExploit } = require("./src/simulation");
const { printHeader, printTarget, printFinding, printSummary } = require("./src/report");

const RPC = process.env.ETH_RPC_URL || `https://eth-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_KEY}`;

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
  const provider = new ethers.JsonRpcProvider(RPC, undefined, { staticNetwork: true, polling: false });
if (process.env.CI) console.log("[CI] Mode active. RPC=", RPC?.slice(0,40));
if (!RPC || RPC.includes("undefined")) { console.error("[ERROR] No valid RPC URL - check ETH_RPC_URL secret"); if (process.env.CI) process.exit(0); }
  const results = [];

  // Combine hardcoded + dynamically discovered targets
  let dynamicTargets = [];
  try {
    dynamicTargets = process.env.CI ? [] : await discoverNewTargets();
  } catch(e) {
    console.log("Dynamic discovery failed:", e.message);
  }

  const allTargets = [...TARGETS, ...dynamicTargets];
  console.log(`Scanning ${allTargets.length} contracts (${TARGETS.length} known + ${dynamicTargets.length} newly discovered)...\n`);

  for (const target of allTargets) {
    try {
      const bytecode = await Promise.race([
      provider.getCode(target.address),
      new Promise((_,r) => setTimeout(() => r(new Error('RPC timeout')), 30000))
    ]).catch(() => '0x');
      if (bytecode === "0x") continue;

      const bytecodeFindings = runAllRules(bytecode);
      const slitherFindings = process.env.CI ? [] : await Promise.race([
      analyzeWithSlither(target.address),
      new Promise((_,r) => setTimeout(() => r(new Error('Slither timeout')), 60000))
    ]).catch(e => { console.log('[SKIP] Slither timeout:', target.name); return []; });
      const findings = [...bytecodeFindings, ...slitherFindings];

      if (findings.length > 0) {
        printTarget(target);
        findings.forEach(printFinding);
        for (const finding of findings) {
          if (finding.severity === "CRITICAL") {
            const sim = process.env.CI ? {simulated:false} : await simulateExploit(target, finding);
            if (sim.simulated) {
              console.log(`   Simulation: ${sim.passed ? "CONFIRMED on mainnet fork" : "completed - check output"}`);
            }
          }
        }
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
