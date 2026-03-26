import React from 'react';

const PAGE_SIZES = [25, 50, 100];
const MAX_PAGES = 7;

interface Props {
  total:      number;
  page:       number;
  pageSize:   number;
  onPage:     (p: number) => void;
  onPageSize: (ps: number) => void;
}

const Pagination: React.FC<Props> = ({ total, page, pageSize, onPage, onPageSize }) => {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to   = Math.min(total, page * pageSize);

  if (total === 0) return null;

  const pages: (number | '…')[] = [];
  if (totalPages <= MAX_PAGES) {
    for (let i = 1; i <= totalPages; i++) pages.push(i);
  } else {
    pages.push(1);
    if (page > 3) pages.push('…');
    for (let i = Math.max(2, page - 1); i <= Math.min(totalPages - 1, page + 1); i++) pages.push(i);
    if (page < totalPages - 2) pages.push('…');
    pages.push(totalPages);
  }

  return (
    <div className="flex items-center justify-between px-5 py-3 border-t border-gray-700/60 text-xs text-gray-400 gap-3 flex-wrap">
      <div className="flex items-center gap-1.5">
        <span className="text-gray-500">Show</span>
        {PAGE_SIZES.map(ps => (
          <button
            key={ps}
            onClick={() => { onPageSize(ps); onPage(1); }}
            className={`px-2.5 py-1 rounded-lg transition font-medium ${
              pageSize === ps
                ? 'bg-blue-600 text-white'
                : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
            }`}
          >
            {ps}
          </button>
        ))}
      </div>

      <span className="text-gray-500">{from}–{to} of {total}</span>

      <div className="flex items-center gap-1">
        <button
          onClick={() => onPage(page - 1)}
          disabled={page <= 1}
          className="px-2.5 py-1 rounded-lg bg-gray-700 hover:bg-gray-600 disabled:opacity-30 disabled:cursor-not-allowed transition"
        >
          ‹
        </button>
        {pages.map((p, i) =>
          p === '…' ? (
            <span key={`e${i}`} className="px-1.5 text-gray-600">…</span>
          ) : (
            <button
              key={p}
              onClick={() => onPage(p as number)}
              className={`px-2.5 py-1 rounded-lg transition font-medium ${
                page === p
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
              }`}
            >
              {p}
            </button>
          )
        )}
        <button
          onClick={() => onPage(page + 1)}
          disabled={page >= totalPages}
          className="px-2.5 py-1 rounded-lg bg-gray-700 hover:bg-gray-600 disabled:opacity-30 disabled:cursor-not-allowed transition"
        >
          ›
        </button>
      </div>
    </div>
  );
};

export default Pagination;
