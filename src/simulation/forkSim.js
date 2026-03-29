const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const RPC_URL = process.env.ETH_RPC_URL || 'https://eth-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_KEY';
const SIM_DIR = path.join(__dirname, '../../../foundry-sims');

function ensureFoundryProject() {
  if (!fs.existsSync(SIM_DIR)) {
    console.log('[SIM] Initialising Foundry project...');
    execSync(`cd ${path.dirname(SIM_DIR)} && forge init foundry-sims --no-git`, { stdio: 'inherit' });
  }
}

function generatePoCContract(contractAddress, vulnType) {
  const contractName = `PoC_${contractAddress.slice(2, 10)}`;
  const template = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "forge-std/Test.sol";

interface ITarget {
    function deposit(uint256) external payable;
    function withdraw(uint256) external;
    function balanceOf(address) external view returns (uint256);
}

contract ${contractName} is Test {
    ITarget target = ITarget(${contractAddress});
    address attacker = makeAddr("attacker");

    function setUp() public {
        vm.createSelectFork("${RPC_URL}");
        vm.deal(attacker, 100 ether);
        vm.label(${contractAddress}, "TARGET");
    }

    // Auto-generated PoC for detected vuln: ${vulnType}
    function test_exploit() public {
        vm.startPrank(attacker);
        uint256 before = attacker.balance;
        console.log("[PoC] ETH before:", before / 1e18, "ETH");

        // Simulation probe — fork traces all internal calls
        (bool ok,) = ${contractAddress}.call{value: 0.1 ether}(
            abi.encodeWithSignature("deposit(uint256)", 0.1 ether)
        );
        console.log("[PoC] Deposit ok:", ok);
        console.log("[PoC] ETH after: ", attacker.balance / 1e18, "ETH");
        vm.stopPrank();
    }
}
`;
  const testDir = path.join(SIM_DIR, 'test');
  fs.mkdirSync(testDir, { recursive: true });
  const testFile = path.join(testDir, `${contractName}.t.sol`);
  fs.writeFileSync(testFile, template);
  console.log(`[SIM] PoC written → ${testFile}`);
  return contractName;
}

function runForkSim(contractAddress, vulnType = 'unknown') {
  console.log(`\n[SIM] ══════════════════════════════════════`);
  console.log(`[SIM] Target   : ${contractAddress}`);
  console.log(`[SIM] VulnType : ${vulnType}`);
  console.log(`[SIM] ══════════════════════════════════════`);
  ensureFoundryProject();
  const contractName = generatePoCContract(contractAddress, vulnType);
  try {
    const result = execSync(
      `cd ${SIM_DIR} && forge test --match-contract ${contractName} -vvvv --fork-url "${RPC_URL}" 2>&1`,
      { timeout: 120000, encoding: 'utf8' }
    );
    console.log('[SIM] TRACE:\n', result);
    const reportDir = path.join(__dirname, '../../reports');
    fs.mkdirSync(reportDir, { recursive: true });
    const reportPath = path.join(reportDir, `sim_${contractAddress.slice(2,10)}_${Date.now()}.txt`);
    fs.writeFileSync(reportPath, result);
    console.log(`[SIM] Report saved → ${reportPath}`);
    return { success: true, trace: result, reportPath };
  } catch (err) {
    const out = err.stdout || err.message;
    console.log('[SIM] Output:\n', out);
    return { success: false, trace: out };
  }
}

module.exports = { runForkSim };

if (require.main === module) {
  const [,, addr, vuln] = process.argv;
  if (!addr) { console.error('Usage: node forkSim.js <contractAddress> [vulnType]'); process.exit(1); }
  runForkSim(addr, vuln || 'probe');
}
