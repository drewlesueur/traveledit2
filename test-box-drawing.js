const assert = require('node:assert/strict');
const { drawBoxCharacter, isBoxCharacter } = require('./public/text-controls');
const arms = { '─': 10, '│': 5, '┌': 6, '┐': 12, '└': 3, '┘': 9, '├': 7, '┤': 13, '┬': 14, '┴': 11, '┼': 15 };
for (const [width, height] of [[8, 16], [19, 38], [23, 46], [29, 57]]) {
  for (const [char, directions] of Object.entries(arms)) {
    const pixels = new Set();
    const ctx = { fillRect(x, y, w, h) {
      assert.ok([x, y, w, h].every(Number.isInteger));
      assert.ok(x >= 0 && y >= 0 && x + w <= width && y + h <= height);
      for (let row = y; row < y + h; row++) for (let col = x; col < x + w; col++) {
        const key = col + ',' + row;
        assert.ok(!pixels.has(key), 'no overdraw at translucent joins'); pixels.add(key);
      }
    } };
    assert.equal(drawBoxCharacter(ctx, char, 0, 0, width, height), true);
    assert.equal([...pixels].some(p => p.endsWith(',0')), !!(directions & 1), char + ' north');
    assert.equal([...pixels].some(p => p.startsWith((width - 1) + ',')), !!(directions & 2), char + ' east');
    assert.equal([...pixels].some(p => p.endsWith(',' + (height - 1))), !!(directions & 4), char + ' south');
    assert.equal([...pixels].some(p => p.startsWith('0,')), !!(directions & 8), char + ' west');
  }
  // A three-cell line must cover every pixel at its center, including joins.
  for (const vertical of [false, true]) {
    const pixels = new Set();
    const ctx = { fillRect(x, y, w, h) { for (let row = y; row < y + h; row++) for (let col = x; col < x + w; col++) pixels.add(col + ',' + row); } };
    for (let i = 0; i < 3; i++) drawBoxCharacter(ctx, vertical ? '│' : '─', vertical ? 0 : i * width, vertical ? i * height : 0, width, height);
    const stroke = Math.max(1, Math.round(Math.min(width, height) / 12));
    const center = Math.floor(((vertical ? width : height) - stroke) / 2);
    for (let i = 0; i < 3 * (vertical ? height : width); i++) assert.ok(pixels.has(vertical ? center + ',' + i : i + ',' + center));
  }
}
for (const char of ['A', '░', '😀', 'toString']) {
  assert.equal(isBoxCharacter(char), false);
  assert.equal(drawBoxCharacter({ fillRect() { throw Error('ordinary text was drawn as a box'); } }, char, 0, 0, 10, 20), false);
}
console.log('Canvas box-character geometry checks passed');
const scaledPixels = new Set();
drawBoxCharacter({ fillRect(x, y, w, h) { for (let row = y; row < y + h; row++) for (let col = x; col < x + w; col++) scaledPixels.add(col + ',' + row); } }, '─', 0, 0, 22, 46, 3);
const paintedRows = new Set([...scaledPixels].map(point => Number(point.split(',')[1])));
assert.equal(paintedRows.size, 3, 'three backing pixels keep a line visible on the scaled editor canvas');
assert.equal(scaledPixels.size, 22 * 3);
