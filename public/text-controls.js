// Reusable text-style controls for TravelEdit and embedding applications.
(function (host) {
  'use strict';
  function styles() {
    if (document.getElementById('teui-styles')) return;
    const style = document.createElement('style'); style.id = 'teui-styles';
    style.textContent = '.teui-bar[hidden]{display:none}.teui-bar{padding:4px;background:var(--teui-background,Canvas);color:var(--teui-color,CanvasText);font:var(--teui-font,13px monospace)}.teui-trigger{font:inherit;color:inherit;background:transparent;border:0;padding:3px;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer}.teui-popup{position:fixed;z-index:1000;box-sizing:border-box;max-width:calc(100vw - 20px);overflow:auto;padding:7px;border:1px solid currentColor;background:var(--teui-background,Canvas);color:var(--teui-color,CanvasText);box-shadow:var(--teui-shadow,5px 5px 0 #0006);font:var(--teui-font,13px monospace)}.teui-popup button{display:block;width:100%;border:0;background:transparent;color:inherit;font:inherit;padding:7px 3px;text-align:left;cursor:pointer;overflow-wrap:anywhere}.teui-popup button:hover,.teui-popup button:focus-visible{background:Highlight;color:HighlightText;outline:none}.teui-popup button:disabled{opacity:.5;cursor:default}.teui-caption{white-space:pre;margin-bottom:4px;overflow:hidden}.teui-note{font-size:12px;white-space:pre-wrap;padding:4px 2px}.teui-popup button.teui-separated{border-top:1px dashed currentColor;margin-top:5px}';
    document.head.append(style);
  }
  function button(label, action, options = {}) {
    styles();
    const element = document.createElement('button');
    element.type = 'button'; element.textContent = label; element.onclick = action;
    if (options.trigger) element.className = 'teui-trigger';
    if (options.separator) element.classList.add('teui-separated');
    if (options.hasPopup) element.setAttribute('aria-haspopup', 'dialog');
    element.disabled = !!options.disabled;
    return element;
  }
  function bar(after) {
    styles();
    const element = document.createElement('div'); element.className = 'teui-bar';
    after.insertAdjacentElement('afterend', element);
    return element;
  }
  function createMenu(trigger, { width = 290, onClose = () => {} } = {}) {
    styles();
    let entries = [], destroyed = false;
    trigger.setAttribute('aria-haspopup', 'dialog');
    trigger.setAttribute('aria-expanded', 'false');
    function position(entry) {
      const view = host.visualViewport;
      const height = view?.height || host.innerHeight, viewportWidth = view?.width || host.innerWidth;
      const x = view?.offsetLeft || 0, y = view?.offsetTop || 0;
      entry.element.style.maxHeight = Math.max(1, height - 20) + 'px';
      const anchor = entry.anchor.getBoundingClientRect(), box = entry.element.getBoundingClientRect();
      let left = anchor.left, top = anchor.bottom + 6;
      if (entry.parent) {
        left = anchor.right + 7; top = anchor.top;
        if (left + box.width > x + viewportWidth - 10) left = anchor.left - box.width - 7;
        if (left < x + 10) left = anchor.left + 12;
      } else if (top + box.height > y + height - 10) top = anchor.top - box.height - 6;
      entry.element.style.left = Math.max(x + 10, Math.min(left, x + viewportWidth - box.width - 10)) + 'px';
      entry.element.style.top = Math.max(y + 10, Math.min(top, y + height - box.height - 10)) + 'px';
    }
    function closeFrom(index, restoreFocus = false) {
      if (index < 0 || index >= entries.length) return;
      const anchor = entries[index].anchor;
      for (const entry of entries.splice(index)) { entry.observer?.disconnect(); entry.element.remove(); }
      if (!entries.length) { trigger.setAttribute('aria-expanded', 'false'); onClose(); }
      if (restoreFocus && anchor.isConnected !== false) anchor.focus();
    }
    function closeAll() { closeFrom(0); }
    function open(title, { anchor = trigger, parent = null } = {}) {
      if (destroyed) throw new Error('Menu has been destroyed');
      if (parent) {
        const index = entries.findIndex(entry => entry.surface === parent);
        if (index < 0) throw new Error('Parent popup is closed');
        closeFrom(index + 1);
      } else closeAll();
      const element = document.createElement('div'); element.className = 'teui-popup';
      element.style.width = width + 'px'; element.setAttribute('role', 'dialog'); element.setAttribute('aria-label', title);
      const heading = document.createElement('div'); heading.className = 'teui-caption';
      heading.textContent = '┌─ ' + title + ' ───────────────────┐'; element.append(heading);
      document.body.append(element);
      const entry = { element, anchor, parent, disabled: false, buttons: new Map() };
      const surface = entry.surface = {
        element,
        get isOpen() { return entries.includes(entry); },
        button(label, action, options = {}) {
          const item = button(label, action, options); entry.buttons.set(item, !!options.disabled);
          item.disabled = entry.disabled || !!options.disabled; element.append(item); return item;
        },
        note(text, { role } = {}) {
          const note = document.createElement('div'); note.className = 'teui-note'; note.textContent = text;
          if (role) note.setAttribute('role', role); element.append(note); return note;
        },
        radioGroup(label, options, value, change) {
          surface.note(label);
          const choices = options.map(option => typeof option === 'string' ? { value: option, label: option } : option);
          const items = choices.map(option => {
            const item = surface.button('', () => { group.setValue(option.value); change?.(option.value); }, { disabled: option.disabled });
            item.setAttribute('role', 'radio'); return item;
          });
          const group = {
            get value() { return value; },
            setValue(next) {
              value = next;
              items.forEach((item, index) => {
                const selected = choices[index].value === value;
                item.textContent = (selected ? ' ● ' : ' ○ ') + choices[index].label;
                item.setAttribute('aria-checked', String(selected));
              });
            }
          };
          group.setValue(value); return group;
        },
        setDisabled(disabled) { entry.disabled = disabled; for (const [item, original] of entry.buttons) item.disabled = disabled || original; },
        reposition() { if (surface.isOpen) position(entry); },
        close() { closeFrom(entries.indexOf(entry), true); }
      };
      entries.push(entry); trigger.setAttribute('aria-expanded', 'true'); position(entry);
      if (host.ResizeObserver) {
        entry.observer = new host.ResizeObserver(() => { if (surface.isOpen) reposition(); });
        entry.observer.observe(element);
      }
      return surface;
    }
    const outside = event => { if (!trigger.contains(event.target) && !entries.some(entry => entry.element.contains(event.target))) closeAll(); };
    const keyboard = event => {
      if (event.key === 'Escape' && entries.length) { event.preventDefault(); closeFrom(entries.length - 1, true); }
    };
    const reposition = () => { for (const entry of entries) position(entry); };
    document.addEventListener('pointerdown', outside); document.addEventListener('keydown', keyboard);
    host.addEventListener('resize', reposition); host.visualViewport?.addEventListener('resize', reposition);
    return {
      open, closeAll, reposition,
      get isOpen() { return entries.length > 0; },
      destroy() {
        closeAll(); destroyed = true;
        document.removeEventListener('pointerdown', outside); document.removeEventListener('keydown', keyboard);
        host.removeEventListener('resize', reposition); host.visualViewport?.removeEventListener('resize', reposition);
      }
    };
  }
  host.TravelEditUI = { button, bar, createMenu };
  if (typeof module !== 'undefined' && module.exports) module.exports = host.TravelEditUI;
})(typeof window === 'undefined' ? globalThis : window);
