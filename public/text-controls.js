// Inline text controls. Hosts append render().lines to their text buffer and
// call activate(row, column) when the user activates the editor cursor.
(function (host) {
  'use strict';
  function createControls({ onChange = () => {}, onClose = () => {} } = {}) {
    let content = [], stack = [], regions = [], controlRows = new Set(), firstAction = null;
    const button = (label, action, options = {}) => ({ type: 'button', label, action, disabled: !!options.disabled });
    function refresh({ focus = false } = {}) { onChange({ focus }); }
    function closeAll({ focus = false } = {}) {
      const hadPopup = stack.length > 0; stack = [];
      if (hadPopup) { onClose(); refresh({ focus }); }
    }
    function open(title, { parent = null } = {}) {
      if (parent) {
        const index = stack.indexOf(parent);
        if (index < 0) throw new Error('Parent popup is closed');
        stack = stack.slice(0, index + 1);
      } else if (stack.length) { stack = []; onClose(); }
      const popup = {
        title, items: [], disabled: false,
        get isOpen() { return stack.includes(popup); },
        button(label, action, options) { const node = button(label, action, options); popup.items.push(node); return node; },
        note(text) { const node = { type: 'text', text }; popup.items.push(node); return node; },
        radioGroup(label, options, value, change) {
          popup.note(label);
          const choices = options.map(option => typeof option === 'string' ? { value: option, label: option } : option);
          const group = {
            get value() { return value; },
            setValue(next) { value = next; refresh(); }
          };
          for (const option of choices) popup.button(() => (option.value === value ? '[x] ' : '[ ] ') + option.label, () => {
            value = option.value; change?.(value); refresh();
          }, { disabled: option.disabled });
          return group;
        },
        setDisabled(disabled) { popup.disabled = disabled; refresh(); },
        close() {
          const index = stack.indexOf(popup);
          if (index < 0) return;
          stack = stack.slice(0, index);
          if (!stack.length) onClose();
          refresh({ focus: true });
        }
      };
      stack.push(popup); return popup;
    }
    function render({ startRow = 0, width = 60, viewportStart = 0, viewportRows = 30 } = {}) {
      width = Math.max(6, Math.floor(width));
      const lines = [], popup = stack.at(-1);
      regions = []; controlRows = new Set(); firstAction = null;
      const clip = (text, length) => {
        const chars = Array.from(String(typeof text === 'function' ? text() : text));
        return chars.length > length ? chars.slice(0, Math.max(0, length - 1)).join('') + '…' : chars.join('');
      };
      function row(text, node, start = 0, stop = text.length, disabled = false) {
        const index = startRow + lines.length; lines.push(text); controlRows.add(index);
        if (node?.type === 'button') regions.push({ row: index, start, stop, node, disabled: disabled || node.disabled });
      }
      function roots() {
        for (const node of content) {
          const text = clip(node.type === 'button' ? node.label : node.text, width);
          row(text, node, 0, Array.from(text).length);
        }
      }
      function box() {
        const inner = Math.max(1, width - 4);
        row('┌' + clip('─ ' + popup.title + ' ', inner).padEnd(inner, '─') + '┐░');
        for (const node of popup.items) {
          const text = clip(node.type === 'button' ? node.label : node.text, inner);
          row('│' + text.padEnd(inner, ' ') + '│░', node, 1, inner + 1, popup.disabled);
        }
        row('└' + '─'.repeat(inner) + '┘░');
        row(' ' + '░'.repeat(inner + 2));
      }
      // Insert the popup above its trigger when there is less room below it.
      const boxHeight = popup ? popup.items.length + 3 : 0;
      const above = popup && startRow + content.length + boxHeight >= viewportStart + viewportRows;
      if (above) { box(); roots(); } else { roots(); if (popup) box(); }
      firstAction = regions.find(region => !region.disabled && (!popup || popup.items.includes(region.node))) || regions.find(region => !region.disabled) || null;
      return { lines };
    }
    function hit(row, column) { return regions.find(region => region.row === row && column >= region.start && column < region.stop); }
    return {
      button, open, refresh, closeAll, render,
      setContent(nodes) { content = nodes; },
      get isOpen() { return stack.length > 0; },
      get focusTarget() { return firstAction; },
      isControlRow(row) { return controlRows.has(row); },
      capture(row, column) { const region = hit(row, column); return region ? { node: region.node, column: column - region.start } : null; },
      locate(cursor) {
        const region = cursor && regions.find(region => region.node === cursor.node);
        return region ? { row: region.row, column: region.start + Math.min(cursor.column, region.stop - region.start - 1) } : null;
      },
      activate(row, column) {
        const region = hit(row, column);
        if (region) { if (!region.disabled) region.node.action?.(); return true; }
        if (stack.length) { closeAll(); return true; }
        return false;
      },
      destroy() { closeAll(); content = []; regions = []; controlRows.clear(); }
    };
  }
  host.TravelEditUI = { createControls };
  if (typeof module !== 'undefined' && module.exports) module.exports = host.TravelEditUI;
})(typeof window === 'undefined' ? globalThis : window);
