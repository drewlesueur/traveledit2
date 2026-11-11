// Inline text controls. Hosts append render().lines to their text buffer and
// call activate(row, column) when the user activates the editor cursor.
(function (host) {
  'use strict';
  // Directions are north, east, south, west. These are cell graphics, not
  // font glyphs: adjacent cells share the same snapped pixel boundary.
  const boxArms = Object.freeze({ '─': 10, '│': 5, '┌': 6, '┐': 12, '└': 3, '┘': 9,
    '├': 7, '┤': 13, '┬': 14, '┴': 11, '┼': 15, '╭': 6, '╮': 12, '╰': 3, '╯': 9 });
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
    if ([6, 12, 3, 9].includes(arms)) {
      const radius = Math.min(Math.round(Math.min(right - left, bottom - top) * 0.55),
        right - centerX, centerX + stroke - left, bottom - centerY, centerY + stroke - top);
      if (radius > stroke) {
        const east = !!(arms & 2), south = !!(arms & 4);
        // Rasterize one quarter-ring with non-overlapping rectangles. Keeping
        // fillRect also supports TravelEdit's remote canvas command stream.
        for (let row = 0; row < radius; row++) {
          const dy = radius - row - 0.5;
          const start = Math.max(0, Math.ceil(radius - Math.sqrt(radius * radius - dy * dy) - 0.5));
          const inner = radius - stroke;
          const end = dy >= inner ? radius : Math.min(radius, Math.floor(radius - Math.sqrt(inner * inner - dy * dy) - 0.5) + 1);
          fill(east ? centerX + start : centerX + stroke - end,
            south ? centerY + row : centerY + stroke - row - 1, end - start, 1);
        }
        if (east) fill(centerX + radius, centerY, right - centerX - radius, stroke);
        else fill(left, centerY, centerX + stroke - radius - left, stroke);
        if (south) fill(centerX, centerY + radius, stroke, bottom - centerY - radius);
        else fill(centerX, top, stroke, centerY + stroke - radius - top);
        return true;
      }
    }
    // Draw the center once, so translucent colors have no darker joins.
    fill(centerX, centerY, stroke, stroke);
    if (arms & 1) fill(centerX, top, stroke, centerY - top);
    if (arms & 2) fill(centerX + stroke, centerY, right - centerX - stroke, stroke);
    if (arms & 4) fill(centerX, centerY + stroke, stroke, bottom - centerY - stroke);
    if (arms & 8) fill(left, centerY, centerX - left, stroke);
    return true;
  }
  // Visual field chrome only: the host retains its native text/editing model.
  function drawTextInput(context, { x, y, columns, rows, cellWidth, cellHeight, baseline, font,
    viewportWidth = Infinity, viewportHeight = Infinity, label = 'Reply', placeholder = '', borderColor = 'deepskyblue', textColor = 'gray', stroke = 1 }) {
    const oldFill = context.fillStyle, oldFont = context.font, oldBaseline = context.textBaseline;
    context.fillStyle = borderColor;
    columns = Math.max(4, columns); rows = Math.max(3, rows);
    const title = (' ' + label + ' ').slice(0, columns - 2);
    const cell = (char, col, row) => drawBoxCharacter(context, char, x + col * cellWidth, y + row * cellHeight, cellWidth, cellHeight, stroke);
    cell('┌', 0, 0); cell('┐', columns - 1, 0);
    cell('└', 0, rows - 1); cell('┘', columns - 1, rows - 1);
    for (let col = Math.max(1, Math.floor(-x / cellWidth)); col < Math.min(columns - 1, Math.ceil((viewportWidth - x) / cellWidth)); col++) {
      if (col > title.length) cell('─', col, 0);
      cell('─', col, rows - 1);
    }
    for (let row = Math.max(1, Math.floor(-y / cellHeight)); row < Math.min(rows - 1, Math.ceil((viewportHeight - y) / cellHeight)); row++) { cell('│', 0, row); cell('│', columns - 1, row); }
    context.font = font; context.fillStyle = textColor; context.textBaseline = 'top';
    context.fillText(title, x + cellWidth, y + baseline);
    if (placeholder) context.fillText(placeholder.slice(0, columns - 2), x + cellWidth, y + cellHeight + baseline);
    context.fillStyle = oldFill; context.font = oldFont; context.textBaseline = oldBaseline;
  }
  function selectControl(popup, open, refresh, label, options, value, change) {
    const choices = options.map(option => typeof option === 'string' ? { value: option, label: option } : option);
    const trigger = popup.button(() => label + ': ' + (choices.find(option => option.value === value)?.label ?? value) + ' ▾', () => {
      const menu = open(label, { parent: popup, trigger });
      menu.button('< Back', () => menu.close());
      for (const option of choices) menu.button(() => (option.value === value ? '● ' : '○ ') + option.label, () => {
        value = option.value; menu.close(); change?.(value); refresh();
      }, { disabled: option.disabled });
      refresh();
    });
    return { get value() { return value; }, setValue(next) { value = next; refresh(); } };
  }
  function createControls({ onChange = () => {}, onClose = () => {}, onFieldActivate = () => {} } = {}) {
    let content = [], rootLayout = 'column', buttonStyle = 'plain', stack = [], regions = [], controlRows = new Set(), firstAction = null, activating = null;
    let fieldBoxes = [];
    const button = (label, action, options = {}) => ({ type: 'button', label, action, disabled: !!options.disabled });
    const segmented = segments => ({ type: 'segmented', segments, disabled: false });
    function refresh({ focus = false } = {}) { onChange({ focus }); }
    function closeAll({ focus = false } = {}) {
      const hadPopup = stack.length > 0; stack = [];
      if (hadPopup) { onClose(); refresh({ focus }); }
    }
    function open(title, { parent = null, trigger = null } = {}) {
      const origin = activating || (parent ? null : stack[0]?.origin);
      if (parent) {
        const index = stack.indexOf(parent);
        if (index < 0) throw new Error('Parent popup is closed');
        stack = stack.slice(0, index + 1);
      } else if (stack.length) { stack = []; onClose(); }
      const popup = {
        title, parent, origin, trigger, items: [], disabled: false,
        get isOpen() { return stack.includes(popup); },
        button(label, action, options) { const node = button(label, action, options); popup.items.push(node); return node; },
        field(label, value, options = {}) {
          popup.note(label);
          const node = { type: 'field', value: String(value ?? ''), multiline: !!options.multiline, onInput: options.onInput, onBlur: options.onBlur };
          popup.items.push(node); return node;
        },
        note(text) { const node = { type: 'text', text }; popup.items.push(node); return node; },
        select(label, options, value, change) { return selectControl(popup, open, refresh, label, options, value, change); },
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
      regions = []; fieldBoxes = []; controlRows = new Set(); firstAction = null;
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
          const cells = content.map(group => {
            const segments = group.type === 'segmented' ? group.segments : [group];
            let offset = 0;
            const parts = segments.map((node, index) => {
              const value = node.type === 'button' ? node.label : node.text;
              const label = String(typeof value === 'function' ? value() : value);
              const inner = measure(label) + 2, start = offset;
              offset += inner + 1;
              return { node, label, inner, start, stop: offset + (index === segments.length - 1 ? 1 : 0) };
            });
            return { group, parts, width: offset + 1, lines: [
              '┌' + parts.map(part => '─'.repeat(part.inner)).join('┬') + '┐',
              '│' + parts.map(part => ' ' + part.label + ' ').join('│') + '│',
              '└' + parts.map(part => '─'.repeat(part.inner)).join('┴') + '┘'
            ] };
          });
          for (let part = 0; part < 3; part++) {
            const index = startRow + lines.length;
            let offset = 0;
            for (const cell of cells) {
              for (const segment of cell.parts) if (segment.node.type === 'button') {
                regions.push({ row: index, start: offset + segment.start, stop: offset + segment.stop,
                  node: segment.node, part, disabled: cell.group.disabled || segment.node.disabled });
              }
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
      function box(panel = popup, panelWidth = width) {
        const popup = panel;
        const inner = Math.max(3, panelWidth - 4, ...popup.items.filter(node => node.type === 'field')
          .flatMap(node => node.value.split('\n').map(text => measure(text) + 3)));
        row('┌' + clip('─ ' + popup.title + ' ', inner).padEnd(inner, '─') + '┐');
        for (const node of popup.items) {
          if (node.type === 'field') {
            // Keep the field outline separate from the editable text coordinates.
            const fieldWidth = inner - 2;
            const top = rowOrigin + lines.length;
            row('│┌' + '─'.repeat(fieldWidth) + '┐│');
            const fieldLines = node.value.split('\n');
            fieldLines.forEach((text, fieldLine) => {
              row('││' + text + ' '.repeat(fieldWidth - measure(text)) + '││', node, 2, 2 + Math.max(1, measure(text) + 1), popup.disabled);
              regions.at(-1).fieldLine = fieldLine;
            });
            row('│└' + '─'.repeat(fieldWidth) + '┘│');
            fieldBoxes.push({ node, top, bottom: rowOrigin + lines.length - 1, start: columnOrigin + 1, stop: columnOrigin + inner + 1, disabled: popup.disabled });
            continue;
          }
          const text = clip(node.type === 'button' ? node.label : node.text, inner);
          row('│' + text.padEnd(inner, ' ') + '│', node, 1, inner + 1, popup.disabled);
        }
        row('└' + '─'.repeat(inner) + '┘');
      }
      // Insert the popup above its trigger when there is less room below it.
      const boxHeight = popup ? popup.items.reduce((height, node) => height + (node.type === 'field' ? node.value.split('\n').length + 2 : 1), 2) : 0;
      const above = popup && startRow + (rootLayout === 'row' ? Math.min(1, content.length) * (buttonStyle === 'box' ? 3 : 1) : content.length) + boxHeight >= viewportStart + viewportRows;
      let floating = null;
      const overlays = [];
      if (overlay) {
        roots();
        const rootCount = lines.length;
        for (const panel of stack) {
          const parent = overlays.at(-1);
          const height = panel.items.reduce((height, node) => height + (node.type === 'field' ? node.value.split('\n').length + 2 : 1), 2);
          let panelWidth = width;
          let panelRow, panelColumn;
          if (!parent) {
            panelColumn = Math.max(0, viewportColumn);
            const panelAbove = startRow + rootCount + height >= viewportStart + viewportRows;
            panelRow = panelAbove && startRow - height >= viewportStart ? startRow - height : startRow + rootCount;
          } else {
            // Anchor to the current trigger region, not its old screen position:
            // scrolling or resizing may have moved the parent since activation.
            const trigger = regions.findLast(region => region.node === (panel.trigger || panel.origin?.node));
            const triggerRow = trigger?.row ?? parent.row;
            panelColumn = parent.column;
            const below = viewportStart + viewportRows - triggerRow - 1;
            const above = triggerRow - viewportStart;
            panelRow = height <= below || below >= above ? triggerRow + 1 : triggerRow - height;
          }
          columnOrigin = panelColumn;
          rowOrigin = panelRow - lines.length;
          box(panel, panelWidth);
          const panelLines = lines.splice(rootCount);
          floating = { row: panelRow, column: panelColumn, width: Math.max(...panelLines.map(measure)), lines: panelLines };
          overlays.push(floating);
        }
      } else if (above) { box(); roots(); } else { roots(); if (popup) box(); }
      firstAction = regions.find(region => !region.disabled && (!popup || popup.items.includes(region.node))) || regions.find(region => !region.disabled) || null;
      return { lines, overlay: floating, overlays };
    }
    // Popup regions are appended after the underlying row and take precedence
    // when a compact menu overlays one of its buttons.
    function hit(row, column) { return regions.findLast(region => region.row === row && column >= region.start && column < region.stop); }
    return {
      button, segmented, open, refresh, closeAll, render,
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
        const box = fieldBoxes.find(box => row >= box.top && row <= box.bottom && column >= box.start && column < box.stop);
        if (box) {
          if (box.disabled) return true;
          const targetRow = Math.max(box.top + 1, Math.min(row, box.bottom - 1));
          const field = regions.find(region => region.node === box.node && region.row === targetRow);
          const targetColumn = Math.max(field.start, Math.min(column, field.stop - 1));
          const redirected = targetRow !== row || targetColumn !== column;
          if (redirected) onFieldActivate({ row: targetRow, column: targetColumn });
          return redirected;
        }
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
      destroy() { closeAll(); content = []; regions = []; fieldBoxes = []; controlRows.clear(); }
    };
  }
  // A DOM surface for the same declarative popup API used by text controls.
  // Hosts choose the surface; actions and field models remain independent of it.
  function createDOMControls({ onClose = () => {} } = {}) {
    let stack = [], anchor = null, root = null;
    const elements = new WeakMap(), panels = new Map();
    const valueOf = value => String(typeof value === 'function' ? value() : value ?? '');
    const button = (label, action, options = {}) => ({ type: 'button', label, action, disabled: !!options.disabled });
    function outside(event) { if (root && ![...panels.values()].some(panel => panel.contains(event.target)) && !anchor?.contains(event.target)) closeAll(); }
    function key(event) { if (event.key === 'Escape') { event.preventDefault(); stack.at(-1)?.close(); if (!stack.length) anchor?.focus?.(); } }
    function closeAll() {
      if (!stack.length) return;
      stack = []; for (const panel of panels.values()) panel.remove(); panels.clear(); root = null;
      document.removeEventListener('pointerdown', outside); document.removeEventListener('keydown', key);
      window.removeEventListener('resize', refresh); window.visualViewport?.removeEventListener('resize', refresh);
      onClose();
    }
    function refresh() {
      if (!stack.length) return;
      for (const [popup, panel] of panels) if (!stack.includes(popup)) { panel.remove(); panels.delete(popup); }
      if (!root || !root.isConnected) {
        root = null;
        document.addEventListener('pointerdown', outside); document.addEventListener('keydown', key);
        window.addEventListener('resize', refresh); window.visualViewport?.addEventListener('resize', refresh);
      }
      for (const popup of stack) {
        let panel = panels.get(popup);
        if (!panel) {
          panel = document.createElement('section'); panel.className = 'te-dom-popup';
          panel.addEventListener('scroll', refresh);
          panel.setAttribute('role', 'dialog'); document.body.append(panel); panels.set(popup, panel);
        }
        if (!popup.parent) root = panel;
        panel.setAttribute('aria-label', popup.title);
        let heading = elements.get(popup);
        if (!heading) { heading = document.createElement('strong'); elements.set(popup, heading); }
        heading.textContent = popup.title;
        const scrollTop = panel.scrollTop;
        const wanted = [heading];
        for (const node of popup.items) {
          let el = elements.get(node);
          if (!el) {
            el = document.createElement(node.type === 'button' ? 'button' : node.type === 'field' ? 'textarea' : node.type === 'frame' ? 'iframe' : 'div');
            if (node.type === 'frame') { el.src = node.url; el.title = node.title; }
            if (node.type === 'button') { el.type = 'button'; el.addEventListener('click', () => node.action?.()); }
            if (node.type === 'field') {
              el.rows = node.multiline ? 3 : 1; el.setAttribute('aria-label', node.label);
              el.addEventListener('input', () => { node.value = el.value; node.onInput?.(node.value); });
              el.addEventListener('blur', () => node.onBlur?.());
            }
            elements.set(node, el);
          }
          if (node.type === 'field') { if (document.activeElement !== el) el.value = node.value; }
          else if (node.type !== 'frame') el.textContent = valueOf(node.type === 'button' ? node.label : node.text);
          el.disabled = popup.disabled || node.disabled || false;
          wanted.push(el);
        }
        let close = popup.closeButton;
        if (!close) { close = popup.closeButton = document.createElement('button'); close.type = 'button'; close.textContent = popup.parent ? 'Back' : 'Close'; close.addEventListener('click', () => popup.close()); }
        wanted.push(close);
        for (const el of [...panel.children]) if (!wanted.includes(el)) el.remove();
        wanted.forEach((el, index) => { if (panel.children[index] !== el) panel.insertBefore(el, panel.children[index] || null); });
        panel.scrollTop = scrollTop;
      }
      const rect = anchor?.getBoundingClientRect();
      const bottom = Math.max(8, window.innerHeight - (rect?.top ?? window.innerHeight - 8) + 4);
      for (const popup of stack) {
        const panel = panels.get(popup);
        panel.style.top = '';
        panel.style.bottom = bottom + 'px';
        panel.style.maxHeight = Math.max(100, window.innerHeight - bottom - 8) + 'px';
        const triggerRect = popup.parent && elements.get(popup.trigger)?.getBoundingClientRect();
        if (triggerRect) {
          const below = Math.max(0, window.innerHeight - triggerRect.bottom - 8);
          const above = Math.max(0, triggerRect.top - 8);
          const height = panel.getBoundingClientRect().height;
          if (height <= below || below >= above) {
            panel.style.bottom = 'auto';
            panel.style.top = triggerRect.bottom + 'px';
            panel.style.maxHeight = below + 'px';
          } else {
            panel.style.bottom = (window.innerHeight - triggerRect.top) + 'px';
            panel.style.maxHeight = above + 'px';
          }
        }
      }
    }
    function open(title, { parent = null, trigger = null } = {}) {
      if (parent) {
        const index = stack.indexOf(parent);
        if (index < 0) throw new Error('Parent popup is closed');
        stack = stack.slice(0, index + 1);
      } else if (stack.length) { stack = []; onClose(); }
      const popup = {
        title, parent, trigger, items: [], disabled: false,
        frame(url, title) { const node = { type: 'frame', url, title }; popup.items.push(node); return node; },
        get isOpen() { return stack.includes(popup); },
        button(label, action, options) { const node = button(label, action, options); popup.items.push(node); return node; },
        note(text) { const node = { type: 'text', text }; popup.items.push(node); return node; },
        field(label, value, options = {}) {
          popup.note(label); const node = { type: 'field', label, value: String(value ?? ''), multiline: !!options.multiline, onInput: options.onInput, onBlur: options.onBlur };
          popup.items.push(node); return node;
        },
        select(label, options, value, change) { return selectControl(popup, open, refresh, label, options, value, change); },
        radioGroup(label, options, value, change) {
          popup.note(label);
          for (const option of options.map(option => typeof option === 'string' ? { value: option, label: option } : option)) {
            popup.button(() => (option.value === value ? '● ' : '○ ') + option.label, () => { value = option.value; change?.(value); refresh(); }, { disabled: option.disabled });
          }
          return { get value() { return value; }, setValue(next) { value = next; refresh(); } };
        },
        setDisabled(disabled) { popup.disabled = disabled; refresh(); },
        close() { const index = stack.indexOf(popup); if (index < 0) return; if (!index) closeAll(); else { stack = stack.slice(0, index); refresh(); } }
      };
      stack.push(popup); return popup;
    }
    return { button, open, refresh, closeAll, get isOpen() { return stack.length > 0; },
      setAnchor(element) { anchor = element; }, setContent() {}, destroy: closeAll };
  }
  host.TravelEditUI = { drawTextInput, createDOMControls, createControls, isBoxCharacter, drawBoxCharacter };
  if (typeof module !== 'undefined' && module.exports) module.exports = host.TravelEditUI;
})(typeof window === 'undefined' ? globalThis : window);
