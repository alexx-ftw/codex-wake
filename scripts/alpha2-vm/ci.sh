#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "$0")/../.."
expected=${1:?exact source SHA required}
output=${2:?new output directory required}
[[ $expected =~ ^[a-f0-9]{40}$ && $(git rev-parse HEAD) == "$expected" ]]
[[ -z $(git status --porcelain --untracked-files=normal) ]]
git merge-base --is-ancestor 144e1b08bad400b33964265e22a87b6e49c57b32 "$expected"
mkdir -- "$output"
output=$(cd -- "$output" && pwd)
context=$(mktemp -d)
container=
image="wake-alpha2-lab:$expected"
cleanup() {
  [[ -z $container ]] || docker rm -f "$container" >/dev/null
  rm -rf -- "$context"
}
trap cleanup EXIT
# Export only tracked build sources, never a live checkout, state or binaries.
git archive "$expected" Cargo.toml Cargo.lock rust-toolchain.toml src hooks.json.tmpl \
  hooks/hooks.json scripts/interrupt.sh scripts/alpha2-vm | tar -x -C "$context"
SOURCE_SHA=$expected SOURCE_TREE=$(git rev-parse 'HEAD^{tree}') node --input-type=module - "$context" <<'JS'
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
const root=process.argv[2], files={};
function walk(dir) {
  for (const item of fs.readdirSync(dir,{withFileTypes:true})) {
    const full=path.join(dir,item.name);
    if(item.isDirectory()) walk(full);
    else { if(!item.isFile()) throw Error('non-regular source');
      files[path.relative(root,full)]=createHash('sha256').update(fs.readFileSync(full)).digest('hex'); }
  }
}
walk(root);
fs.writeFileSync(path.join(root,'source.json'),JSON.stringify({sha:process.env.SOURCE_SHA,tree:process.env.SOURCE_TREE,
  repository:process.env.GITHUB_REPOSITORY??null,run_id:process.env.GITHUB_RUN_ID??null,
  run_attempt:process.env.GITHUB_RUN_ATTEMPT??null,
  runner_image:{os:process.env.ImageOS??null,version:process.env.ImageVersion??null},files},null,2)+'\n');
JS
docker build --platform linux/amd64 -t "$image" -f "$context/scripts/alpha2-vm/Dockerfile" "$context"
args=(--network none --cap-drop ALL --security-opt no-new-privileges --env LAB_ACCEL=tcg)
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  args=(--network none --cap-drop ALL --security-opt no-new-privileges --device /dev/kvm --env LAB_ACCEL=kvm)
fi
container=$(docker create "${args[@]}" "$image")
status=0
docker start --attach "$container" || status=$?
docker cp "$container:/output/." "$output"
[[ $status == 0 ]]
[[ $(docker inspect --format '{{.State.Status}}' "$container") == exited ]]
[[ $(docker inspect --format '{{.State.ExitCode}}' "$container") == 0 ]]
node scripts/alpha2-vm/receipt.mjs verify "$output" "$expected"
