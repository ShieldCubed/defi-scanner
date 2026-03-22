const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");

const WORK_DIR = "/tmp/defi-scanner";

async function getSourceCode(address) {
  try {
    const { data } = await axios.get(
      `https://sourcify.dev/server/files/any/1/${address}`
    );
    if (data?.files?.length > 0) return { files: data.files };
  } catch (e) {}
  return null;
}

function writeSourceFiles(address, sourceData) {
  const dir = path.join(WORK_DIR, address);
  fs.mkdirSync(dir, { recursive: true });
  for (const file of sourceData.files) {
    if (!file.name.endsWith(".sol")) continue;
    const fullPath = path.join(dir, file.name);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, file.content);
  }
  return { dir };
}

function runSlither(dir) {
  try {
    const output = execSync(
      `slither ${dir} --json - 2>/dev/null`,
      { timeout: 60000, encoding: "utf8" }
    );
    return JSON.parse(output);
  } catch (e) {
    try {
      return JSON.parse(e.stdout || "{}");
    } catch {
      return null;
    }
  }
}

function parseSlitherFindings(slitherOutput) {
  if (!slitherOutput?.results?.detectors) return [];
  const HIGH_IMPACT = ["high", "medium"];
  return slitherOutput.results.detectors
    .filter(d => HIGH_IMPACT.includes(d.impact?.toLowerCase()))
    .map(d => ({
      rule: `SLITHER_${d.check?.toUpperCase()}`,
      severity: d.impact?.toUpperCase(),
      description: d.description?.trim().slice(0, 200),
      pattern: `Slither: ${d.check}`,
      confidence: d.confidence,
    }));
}

async function analyzeWithSlither(address) {
  try {
    console.log(`  -> Fetching source for ${address}...`);
    const sourceData = await getSourceCode(address);
    if (!sourceData) {
      console.log(`  -> No verified source found on Sourcify`);
      return [];
    }
    console.log(`  -> Running Slither...`);
    const { dir } = writeSourceFiles(address, sourceData);
    const output = runSlither(dir);
    const findings = parseSlitherFindings(output);
    fs.rmSync(dir, { recursive: true, force: true });
    console.log(`  -> Slither found ${findings.length} high/medium issues`);
    return findings;
  } catch (e) {
    console.log(`  -> Slither error: ${e.message}`);
    return [];
  }
}

module.exports = { analyzeWithSlither };
