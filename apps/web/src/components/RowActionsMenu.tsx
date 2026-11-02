import { useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from 'react';
import { createPortal } from 'react-dom';

export interface RowAction {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  /** Longer explanation, shown as a tooltip. */
  description?: string;
}

interface Props {
  items: RowAction[];
  /** Accessible name, e.g. "Actions for web-01". */
  label: string;
}

const MENU_GAP = 4;
const VIEWPORT_MARGIN = 8;

/**
 * "Actions" button with a dropdown menu for table rows. The menu renders in document.body with fixed
 * positioning, so a scrolling table cannot clip it, and only exists while open, so long tables stay light.
 */
export function RowActionsMenu({ items, label }: Props) {
  const [open, setOpen] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  // Open below the button, or above it when there is no room; keep it inside the window.
  useLayoutEffect(() => {
    if (!open || !buttonRef.current || !menuRef.current) return;
    const button = buttonRef.current.getBoundingClientRect();
    const menu = menuRef.current.getBoundingClientRect();
    const below = button.bottom + MENU_GAP;
    const top = below + menu.height > window.innerHeight - VIEWPORT_MARGIN
      ? Math.max(VIEWPORT_MARGIN, button.top - MENU_GAP - menu.height)
      : below;
    const left = Math.max(VIEWPORT_MARGIN, Math.min(button.right - menu.width, window.innerWidth - menu.width - VIEWPORT_MARGIN));
    // A layout effect runs before the browser paints, so the menu is never seen at its starting position.
    menuRef.current.style.top = `${top}px`;
    menuRef.current.style.left = `${left}px`;
    // preventScroll: a scroll would close the menu.
    menuRef.current.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus({ preventScroll: true });
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    const onPointerDown = (e: PointerEvent) => {
      const target = e.target as Node;
      if (!menuRef.current?.contains(target) && !buttonRef.current?.contains(target)) close();
    };
    document.addEventListener('pointerdown', onPointerDown);
    // The menu is fixed in place, so it would drift away from its row when the page scrolls.
    window.addEventListener('scroll', close, true);
    window.addEventListener('resize', close);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      window.removeEventListener('scroll', close, true);
      window.removeEventListener('resize', close);
    };
  }, [open]);

  function closeAndRefocus() {
    setOpen(false);
    buttonRef.current?.focus();
  }

  function onMenuKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Escape' || e.key === 'Tab') {
      if (e.key === 'Escape') e.preventDefault();
      closeAndRefocus();
      return;
    }
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp' && e.key !== 'Home' && e.key !== 'End') return;
    e.preventDefault();
    const enabled = Array.from(menuRef.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? []);
    if (enabled.length === 0) return;
    const current = enabled.indexOf(document.activeElement as HTMLButtonElement);
    const next = e.key === 'Home' ? 0
      : e.key === 'End' ? enabled.length - 1
      : e.key === 'ArrowDown' ? (current + 1) % enabled.length
      : (current - 1 + enabled.length) % enabled.length;
    enabled[next].focus();
  }

  return (
    <>
      <button
        ref={buttonRef}
        type="button"
        className="btn-small btn-action row-actions-button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={label}
        onClick={() => setOpen((o) => !o)}
      >
        Actions <span aria-hidden="true">▾</span>
      </button>
      {open && createPortal(
        <div
          ref={menuRef}
          role="menu"
          aria-label={label}
          className="row-actions-menu"
          onKeyDown={onMenuKeyDown}
        >
          {items.map((item) => (
            <button
              key={item.label}
              type="button"
              role="menuitem"
              disabled={item.disabled}
              title={item.description}
              onClick={() => { closeAndRefocus(); item.onClick(); }}
            >
              {item.label}
            </button>
          ))}
        </div>,
        document.body
      )}
    </>
  );
}
