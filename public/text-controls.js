// Inline text controls. Hosts append render().lines to their text buffer and
// call activate(row, column) when the user activates the editor cursor.
(function (host) {
  'use strict';
  // Directions are north, east, south, west. These are cell graphics, not
  // font glyphs: adjacent cells share the same snapped pixel boundary.
  const boxArms = Object.freeze({ '─': 10, '│': 5, '┌': 6, '┐': 12, '└': 3, '┘': 9,
    '├': 7, '┤': 13, '┬': 14, '┴': 11, '┼': 15 });
  const isBoxCharacter = char => Object.hasOwn(boxArms, char);
  function drawBoxCharacter(context, char, x, y, width, height, minimumStroke = 1) {
    if (!isBoxCharacter(char)) return false;
    const left = Math.round(x), top = Math.round(y);
    const right = Math.round(x + width), bottom = Math.round(y + height);
    if (right <= left || bottom <= top) return true;
    const stroke = Math.min(right - left, bottom - top, Math.max(1, Math.ceil(minimumStroke), Math.round(Math.min(right - left, bottom - top) / 12)));
    const centerX = left + Math.floor((right - left - stroke) / 2);
    const centerY = top + Math.floor((bottom - top - stroke) / 2);
    const fill = (a, b, w, h) => { if (w > 0 && h > 0) context.fillRect(a, b, w, h); };
    const arms = boxArms[char];
    // Draw the center once, so translucent colors have no darker joins.
    fill(centerX, centerY, stroke, stroke);
    if (arms & 1) fill(centerX, top, stroke, centerY - top);
    if (arms & 2) fill(centerX + stroke, centerY, right - centerX - stroke, stroke);
    if (arms & 4) fill(centerX, centerY + stroke, stroke, bottom - centerY - stroke);
    if (arms & 8) fill(left, centerY, centerX - left, stroke);
    return true;
  }
  function createControls({ onChange = () => {}, onClose = () => {} } = {}) {
    let content = [], rootLayout = 'column', buttonStyle = 'plain', stack = [], regions = [], controlRows = new Set(), firstAction = null, activating = null;
    const button = (label, action, options = {}) => ({ type: 'button', label, action, disabled: !!options.disabled });
    function refresh({ focus = false } = {}) { onChange({ focus }); }
    function closeAll({ focus = false } = {}) {
      const hadPopup = stack.length > 0; stack = [];
      if (hadPopup) { onClose(); refresh({ focus }); }
    }
    function open(title, { parent = null } = {}) {
      const origin = activating || (parent ? null : stack[0]?.origin);
      if (parent) {
        const index = stack.indexOf(parent);
        if (index < 0) throw new Error('Parent popup is closed');
        stack = stack.slice(0, index + 1);
      } else if (stack.length) { stack = []; onClose(); }
      const popup = {
        title, parent, origin, items: [], disabled: false,
        get isOpen() { return stack.includes(popup); },
        button(label, action, options) { const node = button(label, action, options); popup.items.push(node); return node; },
        field(label, value, options = {}) {
          popup.note(label);
          const node = { type: 'field', value: String(value ?? ''), multiline: !!options.multiline };
          popup.items.push(node); return node;
        },
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
    function render({ startRow = 0, width = 60, viewportStart = 0, viewportRows = 30, measure = text => Array.from(text).length, overlay = false, viewportColumn = 0 } = {}) {
      width = Math.max(6, Math.floor(width));
      const lines = [], popup = stack.at(-1);
      let rowOrigin = startRow, columnOrigin = 0;
      regions = []; controlRows = new Set(); firstAction = null;
      const clip = (text, length) => {
        const chars = Array.from(String(typeof text === 'function' ? text() : text));
        return chars.length > length ? chars.slice(0, Math.max(0, length - 1)).join('') + '…' : chars.join('');
      };
      function row(text, node, start = 0, stop = text.length, disabled = false) {
        const index = rowOrigin + lines.length; lines.push(text); controlRows.add(index);
        if (node?.type === 'button' || node?.type === 'field') regions.push({ row: index, start: start + columnOrigin, stop: stop + columnOrigin, node, text, disabled: disabled || node.disabled });
      }
      function roots() {
        if (rootLayout === 'row' && buttonStyle === 'box' && content.length) {
          const cells = content.map(node => {
            const value = node.type === 'button' ? node.label : node.text;
            const label = String(typeof value === 'function' ? value() : value);
            return { node, width: measure(label) + 4, lines: ['┌' + '─'.repeat(measure(label) + 2) + '┐', '│ ' + label + ' │', '└' + '─'.repeat(measure(label) + 2) + '┘'] };
          });
          for (let part = 0; part < 3; part++) {
            const index = startRow + lines.length;
            let offset = 0;
            for (const cell of cells) {
              if (cell.node.type === 'button') regions.push({ row: index, start: offset, stop: offset + cell.width, node: cell.node, part, disabled: cell.node.disabled });
              offset += cell.width + 1;
            }
            row(cells.map(cell => cell.lines[part]).join(' '));
          }
          return;
        }
        if (rootLayout === 'row' && content.length) {
          const index = startRow + lines.length;
          let text = '';
          for (const node of content) {
            if (text) text += ' ';
            const start = measure(text);
            const value = node.type === 'button' ? node.label : node.text;
            text += String(typeof value === 'function' ? value() : value);
            if (node.type === 'button') regions.push({ row: index, start, stop: measure(text), node, disabled: node.disabled });
          }
          // Keep the entire row; the host editor supplies horizontal scrolling.
          row(text); return;
        }
        for (const node of content) {
          const text = clip(node.type === 'button' ? node.label : node.text, width);
          row(text, node, 0, Array.from(text).length);
        }
      }
      function box() {
        const inner = Math.max(1, width - 4);
        row('┌' + clip('─ ' + popup.title + ' ', inner).padEnd(inner, '─') + '┐░');
        for (const node of popup.items) {
          if (node.type === 'field') {
            // Editable text uses native editor columns, without box padding.
            const fieldLines = node.value.split('\n');
            fieldLines.forEach((text, fieldLine) => {
              row(text, node, 0, Math.max(1, measure(text) + 1), popup.disabled);
              regions.at(-1).fieldLine = fieldLine;
            });
            continue;
          }
          const text = clip(node.type === 'button' ? node.label : node.text, inner);
          row('│' + text.padEnd(inner, ' ') + '│░', node, 1, inner + 1, popup.disabled);
        }
        row('└' + '─'.repeat(inner) + '┘░');
        row(' ' + '░'.repeat(inner + 2));
      }
      // Insert the popup above its trigger when there is less room below it.
      const boxHeight = popup ? popup.items.reduce((height, node) => height + (node.type === 'field' ? node.value.split('\n').length : 1), 3) : 0;
      const above = popup && startRow + (rootLayout === 'row' ? Math.min(1, content.length) * (buttonStyle === 'box' ? 3 : 1) : content.length) + boxHeight >= viewportStart + viewportRows;
      let floating = null;
      if (overlay) {
        roots();
        if (popup) {
          const rootCount = lines.length;
          const anchor = popup.parent && popup.origin;
          const anchorRow = anchor ? anchor.row : startRow;
          columnOrigin = anchor ? Math.max(0, anchor.start - 1) : Math.max(0, viewportColumn);
          const needsAbove = anchor ? anchorRow + 1 + boxHeight >= viewportStart + viewportRows : above;
          const putAbove = needsAbove && anchorRow - boxHeight >= viewportStart;
          const popupRow = putAbove ? anchorRow - boxHeight : anchor ? anchorRow + 1 : startRow + rootCount;
          const addAnchor = () => {
            row(anchor.text);
            regions.push({ ...anchor, node: anchor.node, disabled: anchor.node.disabled });
          };
          rowOrigin = (anchor && !putAbove ? anchorRow : popupRow) - rootCount;
          if (anchor && !putAbove) addAnchor();
          box();
          if (anchor && putAbove) addAnchor();
          floating = { row: anchor && !putAbove ? anchorRow : popupRow, column: columnOrigin, lines: lines.splice(rootCount) };
        }
      } else if (above) { box(); roots(); } else { roots(); if (popup) box(); }
      firstAction = regions.find(region => !region.disabled && (!popup || popup.items.includes(region.node))) || regions.find(region => !region.disabled) || null;
      return { lines, overlay: floating };
    }
    function hit(row, column) { return regions.find(region => region.row === row && column >= region.start && column < region.stop); }
    return {
      button, open, refresh, closeAll, render,
      setContent(nodes, { layout = 'column', style = 'plain' } = {}) { content = nodes; rootLayout = layout; buttonStyle = style; },
      get isOpen() { return stack.length > 0; },
      get focusTarget() { return firstAction; },
      isControlRow(row) { return controlRows.has(row); },
      highlightAt(row, column) {
        const region = hit(row, column);
        if (region) return { start: region.start, stop: region.stop };
        return controlRows.has(row) ? { start: 0, stop: 0 } : null;
      },
      capture(row, column) { const region = hit(row, column) || regions.find(region => region.row === row && region.node.type === 'field'); return region ? { node: region.node, fieldLine: region.fieldLine, part: region.part, column: column - region.start } : null; },
      locate(cursor) {
        const region = cursor && regions.find(region => region.node === cursor.node && region.fieldLine === cursor.fieldLine && region.part === cursor.part);
        return region ? { row: region.row, column: region.start + Math.min(cursor.column, region.stop - region.start - 1) } : null;
      },
      fieldAt(row) { return regions.find(region => region.row === row && region.node.type === 'field' && !region.disabled) || null; },
      activate(row, column) {
        const region = hit(row, column);
        if (region?.node.type === 'field') return false;
        if (region) {
          if (!region.disabled) {
            const opened = stack.find(popup => popup.origin?.node === region.node);
            if (opened) opened.close();
            else {
              activating = { ...region };
              try { region.node.action?.(); } finally { activating = null; }
            }
          }
          return true;
        }
        if (stack.length) { closeAll(); return true; }
        return false;
      },
      destroy() { closeAll(); content = []; regions = []; controlRows.clear(); }
    };
  }
  host.TravelEditUI = { createControls, isBoxCharacter, drawBoxCharacter };
  if (typeof module !== 'undefined' && module.exports) module.exports = host.TravelEditUI;
})(typeof window === 'undefined' ? globalThis : window);
