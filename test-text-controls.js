const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const listeners = () => ({
  events: new Map(),
  addEventListener(name, fn) { if (!this.events.has(name)) this.events.set(name, new Set()); this.events.get(name).add(fn); },
  removeEventListener(name, fn) { this.events.get(name)?.delete(fn); },
  emit(name, event) { for (const fn of this.events.get(name) || []) fn(event); },
  count() { return [...this.events.values()].reduce((n, set) => n + set.size, 0); }
});
const host = { ...listeners(), innerWidth: 320, innerHeight: 600, visualViewport: { ...listeners(), width: 320, height: 600 } };
let doc;
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.style = {}; this.attributes = {}; this.className = ''; this.classList = { add: name => { this.className += ' ' + name; } }; }
  setAttribute(name, value) { this.attributes[name] = value; }
  append(...children) { for (const child of children) { child.parentNode = this; this.children.push(child); } }
  insertAdjacentElement(where, element) { this.parentNode.append(element); }
  contains(element) { return element === this || this.children.some(child => child.contains(element)); }
  remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(child => child !== this); this.parentNode = null; }
  get isConnected() { return !!this.parentNode; }
  focus() { doc.activeElement = this; }
  getBoundingClientRect() {
    const left = parseFloat(this.style.left) || this.rect?.left || 0, top = parseFloat(this.style.top) || this.rect?.top || 0;
    const width = Math.min(parseFloat(this.style.width) || this.rect?.width || 80, host.visualViewport.width - 20);
    const height = Math.min(30 + this.children.length * 26, parseFloat(this.style.maxHeight) || Infinity);
    return { left, top, width, height, right: left + width, bottom: top + height };
  }
}
doc = { ...listeners(), createElement: name => new Element(name), head: new Element('head'), body: new Element('body'),
  getElementById(id) { return [...this.head.children, ...this.body.children].find(element => element.id === id); } };
const observers = [];
host.ResizeObserver = class { constructor(fn) { this.fn = fn; observers.push(this); } observe() {} disconnect() { this.disconnected = true; } };
vm.runInNewContext(fs.readFileSync(__dirname + '/public/text-controls.js', 'utf8'), { window: host, document: doc });
const ui = host.TravelEditUI;
assert.deepEqual(Object.keys(ui).sort(), ['bar', 'button', 'createMenu']);
const trigger = ui.button('[ Tools ]', null, { trigger: true }); trigger.rect = { left: 280, top: 500, width: 40 }; doc.body.append(trigger);
const another = ui.button('[ Other ]', null, { trigger: true }); doc.body.append(another);
assert.equal(doc.head.children.length, 1, 'styles should be installed once');
let closed = 0;
const menu = ui.createMenu(trigger, { onClose() { closed++; } });
const root = menu.open('Tools');
const anchor = root.button('Options ›', null, { hasPopup: true });
const child = menu.open('Options', { parent: root, anchor });
let selected;
const group = child.radioGroup('Quality', [{ value: 'low', label: 'Low' }, { value: 'high', label: 'High' }], 'low', value => { selected = value; });
const choice = child.element.children.find(element => element.textContent === ' ○ High');
choice.onclick();
assert.equal(group.value, 'high'); assert.equal(selected, 'high'); assert.equal(choice.attributes['aria-checked'], 'true');
const unavailable = child.button('Unavailable', null, { disabled: true });
child.setDisabled(true); assert.equal(choice.disabled, true);
child.setDisabled(false); assert.equal(choice.disabled, false); assert.equal(unavailable.disabled, true);
for (const popup of [root, child]) {
  popup.reposition(); const rect = popup.element.getBoundingClientRect();
  assert.ok(rect.left >= 0 && rect.right <= 320 && rect.top >= 0 && rect.bottom <= 600);
}
let prevented = false;
doc.emit('keydown', { key: 'Escape', preventDefault() { prevented = true; } });
assert.equal(prevented, true); assert.equal(child.isOpen, false); assert.equal(root.isOpen, true); assert.equal(doc.activeElement, anchor);
assert.equal(observers[1].disconnected, true);
const first = menu.open('First', { parent: root, anchor });
const second = menu.open('Second', { parent: root, anchor });
assert.equal(first.isOpen, false); assert.equal(second.isOpen, true);
const otherMenu = ui.createMenu(another); const otherRoot = otherMenu.open('Independent');
menu.closeAll(); assert.equal(otherRoot.isOpen, true); assert.equal(closed, 1);
doc.emit('pointerdown', { target: new Element('outside') });
assert.equal(otherRoot.isOpen, false);
otherMenu.destroy(); menu.destroy();
assert.equal(doc.count(), 0); assert.equal(host.count(), 0); assert.equal(host.visualViewport.count(), 0);
assert.ok(observers.every(observer => observer.disconnected));
assert.throws(() => menu.open('Closed'), /destroyed/);
console.log('Reusable TravelEdit text-control checks passed');
