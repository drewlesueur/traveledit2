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
