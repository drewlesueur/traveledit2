// Verify layout sizing against the real shared editor function.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(__dirname + '/public/index.html', 'utf8');
function implementation(name) {
  const start = source.indexOf('function ' + name + '(');
  assert.ok(start >= 0, 'missing ' + name);
  return source.slice(start, source.indexOf('\nfunction ', start + 1));
}

// Host controls must reduce canvas space in CSS-pixel units without changing
// the existing standalone/native-tab heights.
const sizing = {
  inDebugView: false, floatingKeyboard: false, bluetoothKeyboard: false,
  document: { activeElement: null }, theText: {}, searchText: {}, editorCommandText: {}, voiceCommandText: {},
  fx: { fileMode: 'devtracker' },
  canvasHeightFull: 1710, canvasHeightShell: 1710, canvasHeightTerminal: 1710,
  canvasHeightIframe: 1710, canvasHeightKeyboard: 900, canvasHeightKeyboardTerminal: 900,
  setCanvasHeight(height) { sizing.result = height; }, render() {},
  devTracker: { controlsHeight: () => 77, isComposing: () => false },
};
sizing.window = sizing;
vm.createContext(sizing);
vm.runInContext(implementation('setCanvasHeightAccordingly'), sizing);
sizing.setCanvasHeightAccordingly();
assert.equal(sizing.result, 1710 - 77 * 3);
sizing.devTracker.isComposing = () => true;
sizing.setCanvasHeightAccordingly();
assert.equal(sizing.result, 900 - 77 * 3);
sizing.devTracker = { controlsHeight: () => 0, isComposing: () => false };
sizing.fx.fileMode = 'shell';
sizing.setCanvasHeightAccordingly();
assert.equal(sizing.result, 1710);
delete sizing.devTracker;
sizing.setCanvasHeightAccordingly();
assert.equal(sizing.result, 1710);
console.log('Shared TravelEdit host-control sizing checks passed');

// All native Run entry points delegate task sends; ordinary shell Run keeps
// its existing command path.
let sends = 0, commands = [];
const actions = {
  devTracker: { run() { sends++; return true; } },
  handleTouchAreas(event, mapping) { mapping['1right'](); },
  fx: { fileMode: 'shell', selectedRegions: [], lines: ['printf fixture'], cursorLineIndex: 0 },
  runShellCommand(command) { commands.push(command); },
};
actions.window = actions;
vm.createContext(actions);
for (const name of ['runScript', 'saveWrapper', 'touchAreasLongPress']) {
  vm.runInContext(implementation(name), actions);
}
actions.runScript(); actions.saveWrapper(); actions.touchAreasLongPress({}, {});
assert.equal(sends, 3);
actions.devTracker.run = () => false;
actions.saveWrapper();
assert.deepEqual(commands, ['printf fixture']);
console.log('Shared TravelEdit task Run routing checks passed');

// Cursor highlighting uses control hit bounds, including horizontal scroll.
const highlightSource = source.slice(source.indexOf('    // draw line where your cursor is for help with finding'), source.indexOf('    // the selected areas'));
const rectangles = [];
const highlighting = {
  isDark: false, fontWidth: 10, fontHeight: 20, c: { width: 400 },
  fx: { cursorLineIndex: 6, cursorColIndex: 13, offsetX: 4, offsetY: 2 },
  t: { fillRect(...rectangle) { rectangles.push(rectangle); } },
};
vm.createContext(highlighting);
vm.runInContext('function drawHighlight() {' + highlightSource + '\n}', highlighting);
highlighting.drawHighlight();
assert.deepEqual(rectangles.pop(), [0, 80, 1200, 20], 'normal editor line highlighting is unchanged');
highlighting.fx.textControls = { highlightAt: () => ({ start: 10, stop: 23 }) };
highlighting.drawHighlight();
assert.deepEqual(rectangles.pop(), [60, 80, 130, 20], 'control highlight is limited to the scrolled button');
highlighting.fx.textControls.highlightAt = () => ({ start: 0, stop: 0 });
highlighting.drawHighlight();
assert.equal(rectangles.length, 0, 'control gaps do not highlight the whole row');
console.log('Shared TravelEdit control-highlight checks passed');

const taskToolbarMarkup = source.slice(source.indexOf('id="devTrackerToolbar"'), source.indexOf('id=fileToolbar1'));
const taskToolbarActions = [...taskToolbarMarkup.matchAll(/data-task-action="([^"]+)"/g)].map(match => match[1]);
assert.deepEqual(taskToolbarActions, ['status', 'interrupt', 'voice', 'settings', 'diff', 'send', 'accept', 'model', 'review', 'power', 'star', 'attachments', 'screenshot', 'infographic', 'reviews']);
assert.match(taskToolbarMarkup, /data-task-action="send"[^>]*>Send</);
console.log('Shared TravelEdit task-toolbar layout checks passed');

const resizing = {
  innerWidth: 390, innerHeight: 844, screen: { width: 390, height: 844 },
  c: { style: {} }, fx: { fileMode: 'devtracker' }, devTracker: {},
  setCanvasWidth() {}, setCanvasHeight(value) { resizing.result = value; },
  setCanvasHeightAccordingly() { resizing.result = 1710 - 22 * 3; },
};
resizing.window = resizing;
vm.createContext(resizing);
vm.runInContext(implementation('doSizing').replace(/\ndoSizing\(\)\s*$/, ''), resizing);
resizing.doSizing();
assert.equal(resizing.result, 1644, 'task resize retains only the extra status-strip reduction');
resizing.fx.fileMode = 'shell'; resizing.doSizing();
assert.equal(resizing.result, 1710, 'native cmd resize keeps its existing height');
resizing.fx = undefined; resizing.doSizing();
assert.equal(resizing.result, 1710, 'initial sizing works before a tab exists');
console.log('Shared TravelEdit task resize checks passed');

(async () => {
  let finishClose;
  const events = [];
  const closing = {
    pendingTabCloses: new Set(), files: [], fx: { fileMode: 'devtracker', ID: 17 },
    devTracker: { closeFile() { return new Promise(resolve => { finishClose = resolve; }); } },
    saveWorkspace() { events.push('save'); return Promise.resolve(); },
    addParamToCurrentURL() { return '/reloaded'; }, location: {}, alert(message) { events.push(message); },
  };
  closing.window = closing;
  vm.createContext(closing);
  for (const name of ['closeFileServer', 'doRefresh']) vm.runInContext(implementation(name), closing);
  const pending = closing.closeFileServer();
  const refreshed = closing.doRefresh();
  await Promise.resolve();
  assert.deepEqual(events, [], 'refresh must wait for the server close');
  assert.equal(closing.location.href, undefined);
  finishClose(); await pending; await refreshed;
  assert.deepEqual(events, ['save']);
  assert.equal(closing.location.href, '/reloaded');
  assert.equal(closing.pendingTabCloses.size, 0);
  closing.devTracker.closeFile = () => Promise.reject(new Error('fixture close failed'));
  await assert.rejects(closing.closeFileServer(), /fixture close failed/);
  closing.location.href = '';
  await closing.doRefresh();
  assert.equal(events.filter(event => event === 'save').length, 1, 'failed close must block reload and save');
  assert.equal(closing.location.href, '');
  let registered;
  const remoteTab = { fileMode: 'iframe', iframeRegistration: new Promise(resolve => { registered = resolve; }) };
  closing.proxyPath = '/teproxydev';
  const closedURLs = [];
  closing.fetch = async url => { closedURLs.push(url); return { ok: true }; };
  const remoteClose = closing.closeFileServer(remoteTab);
  await Promise.resolve();
  assert.equal(closedURLs.length, 0, 'closing a remote tab waits for its saved ID');
  remoteTab.ID = 99; registered(); await remoteClose;
  assert.deepEqual(closedURLs, ['/teproxydev/myclose?id=99']);
  console.log('Shared TravelEdit close-before-refresh checks passed');
})().catch(error => { console.error(error); process.exitCode = 1; });

// Restoring the saved active index must not invoke the interactive duplicate gesture.
const restoreSelection = source.match(/if \(ust.has\("fileIndex"\)\) \{([\s\S]*?)\n        \}/)[1];
const restoreTabs = { files: [{ ID: 1 }, { ID: 2 }], ust: new URLSearchParams('fileIndex=1'), selected: [] };
restoreTabs.fx = restoreTabs.files[1];
restoreTabs.selectFileIndex = index => restoreTabs.selected.push(index);
vm.createContext(restoreTabs);
vm.runInContext(restoreSelection, restoreTabs);
assert.deepEqual(restoreTabs.selected, [], 'already-selected tab is not selected again on reload');
restoreTabs.fx = restoreTabs.files[0];
vm.runInContext(restoreSelection, restoreTabs);
assert.deepEqual(restoreTabs.selected, ['1'], 'a different saved active tab is still selected');
console.log('Shared TravelEdit active-tab restore checks passed');

const activeClose = { ID: 1, fileMode: 'devtracker' }, inactiveClose = { ID: 2, fileMode: 'devtracker' };
const closeSelection = {
  files: [activeClose, inactiveClose], fx: activeClose,
  selectFileIndex() { throw new Error('closing another tab must not reselect and duplicate the active tab'); },
  render() {}, renderFileDropdown() {}, closeFileServer() { return Promise.resolve(); }, alert() {},
};
vm.createContext(closeSelection);
vm.runInContext(implementation('closeFile'), closeSelection);
closeSelection.closeFile(inactiveClose);
assert.deepEqual(closeSelection.files, [activeClose]);
console.log('Shared TravelEdit inactive-tab close checks passed');

// Desktop edge navigation is available briefly on entry, then yields to keys.
const edgeTimers = new Map(); let nextEdgeTimer = 0;
const edgeContext = {
  surfaceNavigationTimers: new WeakMap(), positionSurfaceNavigation() {},
  setTimeout(fn, ms) { assert.equal(ms, 1000); edgeTimers.set(++nextEdgeTimer, fn); return nextEdgeTimer; },
  clearTimeout(id) { edgeTimers.delete(id); },
};
vm.createContext(edgeContext);
vm.runInContext(implementation('showSurfaceNavigation'), edgeContext);
const desktopEdges = {surfaceNavigation: [{style:{}}, {style:{}}]};
edgeContext.showSurfaceNavigation(desktopEdges);
assert.ok(desktopEdges.surfaceNavigation.every(e => e.style.display === 'block'));
edgeContext.showSurfaceNavigation(desktopEdges, false);
assert.equal(edgeTimers.size, 0, 'leaving cancels the timer');
edgeContext.showSurfaceNavigation(desktopEdges);
assert.equal(edgeTimers.size, 1, 'returning grants a new window');
[...edgeTimers.values()][0]();
assert.ok(desktopEdges.surfaceNavigation.every(e => e.style.display === 'none'), 'hidden areas cannot intercept key touches');
assert.equal(edgeTimers.size, 0);
edgeContext.showSurfaceNavigation({fileMode:'file'});
console.log('Desktop transient edge navigation checks passed');
