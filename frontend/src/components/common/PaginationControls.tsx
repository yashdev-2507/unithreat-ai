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
      className={`flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between px-3.5 py-2.5 border-t border-[#E5E5E5] bg-[#FFFFFF] text-xs text-[#525252] font-sans ${className}`}
    >
      {/* Items Range Summary */}
      <div className="flex items-center gap-2 font-mono text-slate-500 text-[11px]">
        <span>
          Showing <strong className="text-[#0A0A0A]">{startItem}</strong> –{' '}
          <strong className="text-[#0A0A0A]">{endItem}</strong> of{' '}
          <strong className="text-[#2563EB]">{total}</strong> records
        </span>
      </div>

      {/* Controls Container */}
      <div className="flex items-center gap-4 justify-between sm:justify-end">
        {/* Page Limit Selector */}
        {onLimitChange && (
          <div className="flex items-center gap-1.5 font-mono text-[11px]">
            <label htmlFor="pagination-limit-select" className="text-slate-500">
              Rows:
            </label>
            <select
              id="pagination-limit-select"
              value={limit}
              onChange={(e) => onLimitChange(Number(e.target.value))}
              disabled={disabled}
              className="rounded-md border border-[#D4D4D4] bg-[#FFFFFF] px-2 py-1 text-[#0A0A0A] focus-ring font-mono text-xs cursor-pointer hover:border-slate-400 transition-colors"
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
            className={`inline-flex items-center justify-center rounded-md border p-1.5 transition-colors focus-ring ${
              canGoPrevious
                ? 'border-[#E5E5E5] bg-[#FFFFFF] text-[#0A0A0A] hover:bg-[#F5F5F5] hover:border-slate-300'
                : 'border-[#E5E5E5]/60 bg-slate-50 text-slate-400 cursor-not-allowed'
            }`}
            aria-label="Go to previous page"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>

          <span className="px-2 font-mono text-xs text-[#525252]">
            Page <strong className="text-[#0A0A0A]">{page}</strong> / {maxPage}
          </span>

          <button
            type="button"
            onClick={() => onPageChange(page + 1)}
            disabled={!canGoNext}
            className={`inline-flex items-center justify-center rounded-md border p-1.5 transition-colors focus-ring ${
              canGoNext
                ? 'border-[#E5E5E5] bg-[#FFFFFF] text-[#0A0A0A] hover:bg-[#F5F5F5] hover:border-slate-300'
                : 'border-[#E5E5E5]/60 bg-slate-50 text-slate-400 cursor-not-allowed'
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
