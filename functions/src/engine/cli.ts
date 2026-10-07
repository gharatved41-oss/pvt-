import * as admin from 'firebase-admin';
import { SimulationRunner } from './runner';

// Initialize Firebase Admin for standalone / local free-tier execution
if (!admin.apps.length) {
  admin.initializeApp();
}

async function main() {
  const args = process.argv.slice(2);
  const simId = args[0] || process.env.SIMULATION_ID;
  const twinId = args[1] || process.env.TWIN_ID;

  if (!simId || !twinId) {
    console.log('------------------------------------------------------------');
    console.log('VulnTwin AI - Autonomous Security Validation Engine CLI');
    console.log('Usage:');
    console.log('  node lib/engine/cli.js <simId> <twinId>');
    console.log('  npx ts-node src/engine/cli.ts <simId> <twinId>');
    console.log('------------------------------------------------------------');
    process.exit(1);
  }

  console.log(`[VulnTwin BAS Engine] Initiating automated validation for:`);
  console.log(`  Simulation ID : ${simId}`);
  console.log(`  Twin ID       : ${twinId}`);
  
  const runner = new SimulationRunner();
  const result = await runner.executeSimulation(simId, twinId);
  
  console.log(`\n[VulnTwin BAS Engine] Simulation Complete!`);
  console.log(`  Status               : ${result.status}`);
  console.log(`  Compound Risk Score  : ${result.assessment.riskScore}/100 (${result.assessment.compoundRiskLevel})`);
  console.log(`  Compromised Nodes    : ${result.assessment.compromisedNodeIds.join(', ') || 'None'}`);
  console.log(`  Synthetic Records    : ${result.assessment.totalSyntheticRecordsExposed.toLocaleString()}`);
  console.log(`  Events Emitted       : ${result.eventsEmitted}`);
  console.log(`  Execution Duration   : ${result.durationMs}ms`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error('[VulnTwin BAS Engine] Fatal execution error:', err);
    process.exit(1);
  });
}
