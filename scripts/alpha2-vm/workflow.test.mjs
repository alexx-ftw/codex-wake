import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import {test} from 'node:test';

const workflow=fs.readFileSync(new URL('../../.github/workflows/ci.yml',import.meta.url),'utf8');
const jobs={};let current;
// Read only the fixed job-level fields used here; actionlint validates the YAML.
for(const line of workflow.split('\njobs:\n')[1].split('\n')) {
  if(/^  [\w-]+:$/.test(line)) current=jobs[line.slice(2,-1)]={lines:[]};
  else if(current) {
    current.lines.push(line);
    if(line.startsWith('    if: ')) current.condition=line.trim().slice(4).replace(/^\$\{\{\s*|\s*\}\}$/g,'');
    if(line.startsWith('    needs: ')) current.needs=line.trim().slice(7);
  }
}
const startsWith=(value,prefix)=>String(value).toLowerCase().startsWith(prefix.toLowerCase());
function enabled(event,probe='') {
  const selected=id=>{
    const job=jobs[id];
    const condition=!job.condition||Function('github','inputs','startsWith',`return (${job.condition});`)({event_name:event},{probe},startsWith);
    return condition&&(!job.needs||selected(job.needs));
  };
  return Object.keys(jobs).filter(selected);
}
test('laboratory dispatch selects only the VM; existing events/probes retain their routing',()=>{
  assert.deepEqual(Object.keys(jobs),['test','package','package-lifecycle','controller-systemd-qualification','alpha2-vm']);
  for(const probe of ['alpha2-vm-qualification:'+'a'.repeat(40),'alpha2-vm-qualification','alpha2-vm-qualification:bad']) {
    assert.deepEqual(enabled('workflow_dispatch',probe),['alpha2-vm']);
  }
  const normal=['test','package','package-lifecycle'];
  assert.deepEqual(enabled('push'),normal);
  assert.deepEqual(enabled('pull_request'),[...normal,'controller-systemd-qualification']);
  for(const probe of ['manual','webhook-probe']) assert.deepEqual(enabled('workflow_dispatch',probe),normal);
  for(const probe of ['controller-systemd-qualification','cooperative-handoff-qualification','cooperative-upgrade-qualification']) {
    assert.deepEqual(enabled('workflow_dispatch',probe),['controller-systemd-qualification']);
  }
});
test('actual dispatch preflight rejects a moved ref or malformed SHA before build',()=>{
  const sha='a'.repeat(40), block=jobs['alpha2-vm'].lines;
  const checks=block.filter(line=>line.startsWith('          test '));
  assert.equal(checks.length,1);
  for(const [probe,status]of [['alpha2-vm-qualification:'+sha,0],['alpha2-vm-qualification:'+'b'.repeat(40),1],
    ['alpha2-vm-qualification:bad',1],['alpha2-vm-qualification',1]]) {
    const result=spawnSync('bash',['-e','-c',checks[0].trim()],{env:{...process.env,GITHUB_SHA:sha,PROBE:probe}});
    assert.equal(result.status,status,probe);
  }
  const job=block.join('\n');
  assert(job.includes('EXPECTED_SHA: ${{ github.sha }}'));
  assert(job.includes('ref: ${{ github.sha }}'));
  assert(job.includes('bash scripts/alpha2-vm/ci.sh "$EXPECTED_SHA"'));
  assert(!workflow.includes('inputs.expected_sha'));
  assert(!fs.existsSync(new URL('../../.github/workflows/alpha2-vm.yml',import.meta.url)));
});
