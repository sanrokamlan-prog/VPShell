import type { ReactNode } from "react";
import { X } from "lucide-react";

interface DialogProps {
  title: string;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  onClose: () => void;
}
export function Dialog({ title, children, footer, wide, onClose }: DialogProps) {
  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className={`dialog ${wide ? "dialog-wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="dialog-header">
          <h2>{title}</h2>
          <button className="icon-button" type="button" aria-label="关闭" title="关闭" onClick={onClose}>
            <X size={17} />
          </button>
        </header>
        <div className="dialog-body">{children}</div>
        {footer ? <footer className="dialog-footer">{footer}</footer> : null}
      </section>
    </div>
  );
}
