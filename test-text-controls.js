const assert = require('node:assert/strict');
const { createControls } = require('./public/text-controls');
let changes = 0, closed = 0, selected;
const ui = createControls({ onChange() { changes++; }, onClose() { closed++; } });
let root;
const trigger = ui.button('[ Tools > ]', () => {
  root = ui.open('Tools');
  root.button('Display >', () => {
    const child = ui.open('Display', { parent: root });
    child.button('< Back', () => child.close());
    child.radioGroup('Quality', ['low', 'high'], 'low', value => { selected = value; });
    child.button('Unavailable', () => { throw Error('disabled action'); }, { disabled: true });
    ui.refresh({ focus: true });
  });
  ui.refresh({ focus: true });
});
ui.setContent([trigger]);
let lines;
function render(startRow = 10, viewportRows = 30) {
  lines = ui.render({ startRow, width: 24, viewportRows }).lines;
  assert.ok(lines.every(line => Array.from(line).length <= 24));
  return lines;
}
function activate(text, startRow = 10) {
  const index = lines.findIndex(line => line.includes(text));
  assert.ok(index >= 0, text);
  assert.equal(ui.activate(startRow + index, lines[index].startsWith('│') ? 1 : 0), true);
  render(startRow);
}
assert.deepEqual(render(), ['[ Tools > ]']);
const captured = ui.capture(10, 3);
render(20);
assert.deepEqual(ui.locate(captured), { row: 20, column: 3 });
render(); activate('Tools');
assert.ok(ui.isOpen); assert.ok(lines.some(line => line.startsWith('┌')));
activate('Display >'); activate('[ ] high');
assert.equal(selected, 'high'); assert.ok(lines.some(line => line.includes('[x] high')));
activate('Unavailable');
activate('< Back'); assert.equal(root.isOpen, true);
root.setDisabled(true); render(); activate('Display >');
assert.ok(!lines.some(line => line.includes('Quality')));
root.setDisabled(false); render();
const second = createControls(); second.open('Independent');
assert.equal(ui.activate(500, 0), true); assert.equal(closed, 1);
assert.equal(second.isOpen, true); assert.ok(changes > 0);
render(10, 12); activate('Tools'); render(10, 12);
assert.ok(lines[0].startsWith('┌'), 'popup goes above trigger near viewport end');
assert.ok(ui.isControlRow(10));
ui.destroy(); assert.deepEqual(ui.render().lines, []);
second.destroy();
console.log('Inline TravelEdit text-control checks passed');
