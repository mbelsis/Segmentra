type PaginationProps = {
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number) => void;
  onPageSize: (size: number) => void;
  /** What is being listed, for the "Showing x to y of N hosts" text. */
  noun?: string;
  sizes?: number[];
};

/** First / previous / next / last, the visible range, and a rows-per-page picker. */
export function Pagination({ page, pageSize, total, onPage, onPageSize, noun = 'items', sizes = [10, 25, 50, 100] }: PaginationProps) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const current = Math.min(page, totalPages);
  const start = total === 0 ? 0 : (current - 1) * pageSize + 1;
  const end = Math.min(current * pageSize, total);

  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap', fontSize: 13, color: '#5c4633', margin: '10px 0' }}>
      <span>Showing {start} to {end} of {total} {noun}</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <button type="button" className="btn-small btn-secondary" onClick={() => onPage(1)} disabled={current === 1} aria-label="First page">«</button>
        <button type="button" className="btn-small btn-secondary" onClick={() => onPage(current - 1)} disabled={current === 1}>Previous</button>
        <span style={{ padding: '0 10px' }}>Page {current} of {totalPages}</span>
        <button type="button" className="btn-small btn-secondary" onClick={() => onPage(current + 1)} disabled={current === totalPages}>Next</button>
        <button type="button" className="btn-small btn-secondary" onClick={() => onPage(totalPages)} disabled={current === totalPages} aria-label="Last page">»</button>
      </div>
      <label style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        Rows per page
        <select value={pageSize} onChange={(e) => onPageSize(Number(e.target.value))} style={{ padding: '4px 8px', border: '1px solid #d4c9b8', borderRadius: 6 }}>
          {sizes.map((n) => <option key={n} value={n}>{n}</option>)}
        </select>
      </label>
    </div>
  );
}
