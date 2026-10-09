import { useEffect, type ReactNode } from 'react';

type ModalProps = {
  title: string;
  onClose: () => void;
  children: ReactNode;
  /** Buttons shown at the bottom, right aligned. */
  footer?: ReactNode;
  width?: number;
};

/** A simple dialog: closes with Escape or a click on the dark background, never on a click inside. */
export function Modal({ title, onClose, children, footer, width = 560 }: ModalProps) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div
      className="modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="modal-panel" style={{ maxWidth: width }}>
        <div className="modal-header">
          <h3 style={{ margin: 0 }}>{title}</h3>
          <button type="button" className="btn-small btn-secondary" onClick={onClose} aria-label="Close">Close</button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  );
}
