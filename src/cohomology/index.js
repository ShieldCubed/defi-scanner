const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

async function runCohomologyAnalysis(solFile, contractAddress) {
  console.log(`[COHOMOLOGY] Analyzing: ${contractAddress}`);
  
  const stateMapFile = `/tmp/state_map_${contractAddress.slice(2,10)}.json`;
  const reportFile = `/tmp/cohomology_${contractAddress.slice(2,10)}.json`;
  
  try {
    // Step 1: Map state space
    execSync(
      `python3 ${path.join(__dirname, 'stateMapper.py')} "${solFile}" "${stateMapFile}"`,
      { timeout: 30000, encoding: 'utf8' }
    );
    
    // Step 2: Detect holes
    execSync(
      `python3 ${path.join(__dirname, 'holeDetector.py')} "${stateMapFile}" "${reportFile}"`,
      { timeout: 30000, encoding: 'utf8' }
    );
    
    const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
    
    console.log(`[COHOMOLOGY] Risk: ${report.overall_risk} | Holes: ${report.holes_found}`);
    
    // Save to scanner reports directory
    const outDir = path.join(__dirname, '../../reports');
    fs.mkdirSync(outDir, { recursive: true });
    const outPath = path.join(outDir, `cohomology_${contractAddress.slice(2,10)}_${Date.now()}.json`);
    fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
    console.log(`[COHOMOLOGY] Report saved: ${outPath}`);
    
    return report;
  } catch (err) {
    console.log(`[COHOMOLOGY] Error: ${err.message}`);
    return { overall_risk: 'UNKNOWN', holes_found: 0, holes: [], error: err.message };
  }
}

module.exports = { runCohomologyAnalysis };
