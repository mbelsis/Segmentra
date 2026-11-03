import type { ReadinessRefusal } from '../lib/readiness-refusal';

interface Props {
  refusal: ReadinessRefusal;
  /** Start anyway, accepting the notes. Only offered when nothing blocks the deployment. */
  onAccept: () => void;
  onClose: () => void;
}

export function DeploymentReadinessDialog({ refusal, onAccept, onClose }: Props) {
  const blocked = refusal.code === 'readiness_blocked';
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content readiness-dialog" role="dialog" aria-label="Readiness check" onClick={(e) => e.stopPropagation()}>
        <h2>{blocked ? 'These hosts are not ready' : 'Rules will be lost on reboot'}</h2>
        <p>
          {blocked
            ? 'Nothing was deployed. These hosts are getting their first policy and failed the readiness check. Fix them, or create a deployment without them.'
            : 'Nothing has been deployed yet. Segmentra cannot make its rules survive a restart on these hosts, so after a reboot they would run without them until you deploy again.'}
        </p>
        <ul className="readiness-dialog-hosts">
          {refusal.hosts.map((h) => (
            <li key={h.hostname}>
              <strong>{h.hostname}</strong>
              {h.messages.map((m) => <div key={m}>{m}</div>)}
            </li>
          ))}
        </ul>
        <div className="form-actions">
          {!blocked && <button className="btn-primary" onClick={onAccept}>Deploy anyway</button>}
          <button className="btn-secondary" onClick={onClose}>{blocked ? 'Close' : 'Cancel'}</button>
        </div>
      </div>
    </div>
  );
}
