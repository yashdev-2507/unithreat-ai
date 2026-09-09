import type { FC } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';

export interface PaginationControlsProps {
  page: number;
  limit: number;
  total: number;
  hasMore?: boolean;
  onPageChange: (newPage: number) => void;
  onLimitChange?: (newLimit: number) => void;
  disabled?: boolean;
  pageSizeOptions?: number[];
  className?: string;
}

export const PaginationControls: FC<PaginationControlsProps> = ({
  page,
  limit,
  total,
  hasMore = false,
  onPageChange,
  onLimitChange,
  disabled = false,
  pageSizeOptions = [10, 25, 50, 100],
  className = '',
}) => {
  const startItem = total === 0 ? 0 : (page - 1) * limit + 1;
  const endItem = Math.min(page * limit, total);
  const maxPage = Math.max(1, Math.ceil(total / (limit || 1)));

  const canGoPrevious = !disabled && page > 1;
  const canGoNext = !disabled && (hasMore || endItem < total) && page < maxPage;

  return (
    <div
      className={`flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between px-3 py-2 border-t border-[var(--panel-border)] bg-[var(--panel-bg)] text-xs text-slate-300 font-sans ${className}`}
    >
      {/* Items Range Summary */}
      <div className="flex items-center gap-2 font-mono text-slate-400">
        <span>
          Showing <strong className="text-slate-200">{startItem}</strong> –{' '}
          <strong className="text-slate-200">{endItem}</strong> of{' '}
          <strong className="text-slate-200">{total}</strong> items
        </span>
      </div>

      {/* Controls Container */}
      <div className="flex items-center gap-4 justify-between sm:justify-end">
        {/* Page Limit Selector */}
        {onLimitChange && (
          <div className="flex items-center gap-1.5 font-mono">
            <label htmlFor="pagination-limit-select" className="text-slate-400">
              Rows:
            </label>
            <select
              id="pagination-limit-select"
              value={limit}
              onChange={(e) => onLimitChange(Number(e.target.value))}
              disabled={disabled}
              className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-slate-200 focus-ring font-mono text-xs"
              aria-label="Select rows per page"
            >
              {pageSizeOptions.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>
        )}

        {/* Page Buttons */}
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => onPageChange(page - 1)}
            disabled={!canGoPrevious}
            className={`inline-flex items-center justify-center rounded border p-1.5 transition-colors focus-ring ${
              canGoPrevious
                ? 'border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700'
                : 'border-slate-800 bg-slate-900/50 text-slate-600 cursor-not-allowed'
            }`}
            aria-label="Go to previous page"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>

          <span className="px-2 font-mono text-slate-300">
            Page <strong className="text-slate-100">{page}</strong> / {maxPage}
          </span>

          <button
            type="button"
            onClick={() => onPageChange(page + 1)}
            disabled={!canGoNext}
            className={`inline-flex items-center justify-center rounded border p-1.5 transition-colors focus-ring ${
              canGoNext
                ? 'border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700'
                : 'border-slate-800 bg-slate-900/50 text-slate-600 cursor-not-allowed'
            }`}
            aria-label="Go to next page"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
