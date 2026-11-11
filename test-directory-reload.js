// Run the real shared editor functions with deferred network replies to cover
// duplicate tabs created before the first directory request has completed.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/public/index.html', 'utf8');
function implementation(name) {
  const start = source.indexOf('function ' + name + '(');
  assert.ok(start >= 0, 'missing ' + name);
  return source.slice(start, source.indexOf('\nfunction ', start + 1));
}
let nextID = 0;
const pending = [];
const noop = () => {};
const context = {
  console, Promise, JSON, Math, Response,
  files: [], fx: null, fileToken: 'fixture', maxLines: 30, isGitBash: false,
  proxyPath: '/editor',
  getUniqueID: () => ++nextID,
  makeFile: fullPath => ({ fullPath, fileMode: 'file', lines: [], undo: {}, fileErrors: {}, cursorColIndex: 0 }),
  fetch: () => new Promise(resolve => pending.push(resolve)),
  calcMarginLeft: () => 2, md5: () => 'fixture-md5',
  processPathDecorator: noop, selectFileInDirectory: noop,
  ensureCursorInScreen: noop, updateCursorXY: noop, render: noop,
  verifyLoadedMD5: noop,
  alert: message => { throw new Error(message); },
};
context.window = context;
context.addFileToList = file => context.files.push(file);
context.setCurrentFile = file => { context.fx = file; };
vm.createContext(context);
for (const name of ['normalizeFullPath', 'duplicateFile', 'addFile', 'fetchFile', 'reloadFile']) {
  vm.runInContext(implementation(name), context);
}
async function run() {
  const first = context.addFile('/fixture', {}, 1);
  const second = context.addFile('/fixture', {}, 2);
  assert.equal(pending.length, 1);
  assert.equal(second.fileMode, 'file'); // Still waiting for directory metadata.
  pending.shift()(new Response('..\nexample.txt', { headers: { 'X-Is-Dir': '1' } }));
  await first.loadPromise;
  assert.equal(first.fileMode, 'directory');
  assert.equal(second.fileMode, 'directory');
  assert.equal(second.lines, first.lines);

  // Explicit refresh must propagate type changes too (e.g. a path replaced by
  // a directory, or a tab restored with a stale type).
  second.fileMode = 'file';
  const reloaded = context.reloadFile(first);
  pending.shift()(new Response('..\nnew.txt', { headers: { 'X-Is-Dir': '1' } }));
  await reloaded;
  assert.equal(second.fileMode, 'directory');
  assert.equal(second.lines, first.lines);
  assert.equal(second.lines[1], 'new.txt');
  console.log('Shared TravelEdit duplicate-directory checks passed');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
