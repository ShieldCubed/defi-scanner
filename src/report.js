const chalk = require("chalk");

const SEVERITY_COLORS = {
  CRITICAL: chalk.bgRed.white.bold,
  HIGH: chalk.bgYellow.black.bold,
  MEDIUM: chalk.bgBlue.white.bold,
  LOW: chalk.gray,
};

function printHeader() {
  console.log("\n" + chalk.cyan("═".repeat(60)));
  console.log(chalk.cyan.bold("   DEFI VULNERABILITY SCANNER"));
  console.log(chalk.cyan("   Ethereum Mainnet — " + new Date().toISOString()));
  console.log(chalk.cyan("═".repeat(60)) + "\n");
}

function printTarget(protocol) {
  console.log(chalk.white.bold(`\n📋 ${protocol.name}`));
  console.log(chalk.gray(`   TVL:      $${(protocol.tvl / 1e6).toFixed(2)}M`));
  console.log(chalk.gray(`   Category: ${protocol.category}`));
  console.log(chalk.gray(`   Address:  ${protocol.address}`));
}

function printFinding(finding) {
  const color = SEVERITY_COLORS[finding.severity] || chalk.white;
  console.log(`\n   ${color(` ${finding.severity} `)} ${chalk.white.bold(finding.rule)}`);
  console.log(chalk.gray(`   ${finding.description}`));
  console.log(chalk.dim(`   Pattern: ${finding.pattern}`));
}

function printSummary(results) {
  const total = results.reduce((a, r) => a + r.findings.length, 0);
  const critical = results.reduce((a, r) =>
    a + r.findings.filter(f => f.severity === "CRITICAL").length, 0);
  const high = results.reduce((a, r) =>
    a + r.findings.filter(f => f.severity === "HIGH").length, 0);

  console.log("\n" + chalk.cyan("═".repeat(60)));
  console.log(chalk.cyan.bold("   SCAN SUMMARY"));
  console.log(chalk.cyan("═".repeat(60)));
  console.log(chalk.white(`   Protocols scanned: ${results.length}`));
  console.log(chalk.white(`   Total findings:    ${total}`));
  console.log(SEVERITY_COLORS.CRITICAL(`   Critical:          ${critical}`));
  console.log(SEVERITY_COLORS.HIGH(`   High:              ${high}`));
  console.log(chalk.cyan("═".repeat(60)) + "\n");
}

function saveResults(results) {
  const fs = require("fs");
  const output = {
    timestamp: new Date().toISOString(),
    findings: results.map(r => ({
      name: r.name,
      address: r.address,
      tvl: r.tvl,
      category: r.category,
      findings: r.findings,
    }))
  };
  fs.writeFileSync("scan-output.json", JSON.stringify(output, null, 2));
  console.log(`\nResults saved to scan-output.json`);
}
module.exports = { printHeader, printTarget, printFinding, printSummary, saveResults };
```

Then add secrets to GitHub:
```
github.com/ShieldCubed/defi-scanner → Settings → Secrets → Actions → New secret
Name: ALCHEMY_KEY → paste your key
Name: ETHERSCAN_KEY → paste your key
