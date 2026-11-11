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
assert.deepEqual(taskToolbarActions, ['status', 'interrupt', 'voice', 'settings', 'diff', 'send', 'accept']);
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
