const fs = require('fs');
const path = require('path');

const VENICE_API = 'https://api.venice.ai/api/v1/chat/completions';
const MODEL = 'llama-3.3-70b';

async function generateReport(traceText, contractAddress, vulnType) {
  console.log('[VENICE] Generating AI vulnerability report...');

  const prompt = `You are an expert DeFi security researcher. Analyze this Foundry fork simulation trace and generate a formal vulnerability report.

Contract Address: ${contractAddress}
Vulnerability Type: ${vulnType}

FORGE TRACE:
${traceText.slice(0, 6000)}

Generate a structured report with these exact sections:
1. EXECUTIVE SUMMARY (2-3 sentences, CRITICAL/HIGH/MEDIUM/LOW severity)
2. TECHNICAL FINDINGS (each: title, severity, evidence from trace)
3. ATTACK VECTOR (numbered step-by-step)
4. FINANCIAL IMPACT (estimated max loss USD)
5. REMEDIATION (specific Solidity fixes)
6. SIMILAR EXPLOITS (past DeFi hacks using same pattern)`;

  const response = await fetch(VENICE_API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env.VENICE_API_KEY}`
    },
    body: JSON.stringify({
      model: MODEL,
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 2000,
      temperature: 0.2
    })
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Venice API ${response.status}: ${err}`);
  }

  const data = await response.json();
  const report = data.choices[0].message.content;

  const reportDir = path.join(__dirname, '../../reports');
  fs.mkdirSync(reportDir, { recursive: true });
  const reportPath = path.join(reportDir, `ai_report_${contractAddress.slice(2,10)}_${Date.now()}.md`);

  const fullReport = [
    '# DeFi Scanner AI Vulnerability Report',
    `**Contract:** \`${contractAddress}\``,
    `**Type:** ${vulnType}`,
    `**Generated:** ${new Date().toISOString()}`,
    `**Model:** ${MODEL} via Venice AI`,
    '', '---', '', report
  ].join('\n');

  fs.writeFileSync(reportPath, fullReport);
  console.log('[VENICE] Report saved:', reportPath);
  return { report, reportPath };
}

if (require.main === module) {
  const [,, traceFile, addr, vuln] = process.argv;
  if (!traceFile || !addr) {
    console.error('Usage: node veniceReport.js <traceFile> <address> [vulnType]');
    process.exit(1);
  }
  if (!process.env.VENICE_API_KEY) {
    console.error('❌ Set VENICE_API_KEY first');
    process.exit(1);
  }
  const trace = fs.readFileSync(traceFile, 'utf8');
  generateReport(trace, addr, vuln || 'unknown')
    .then(({ report, reportPath }) => {
      console.log('\n=== REPORT PREVIEW ===\n');
      console.log(report.slice(0, 1500));
      console.log('\n[Full report saved to:', reportPath, ']');
    })
    .catch(err => { console.error('❌', err.message); process.exit(1); });
}

module.exports = { generateReport };
