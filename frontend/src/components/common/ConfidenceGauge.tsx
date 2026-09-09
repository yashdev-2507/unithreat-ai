import type { FC } from 'react';

export interface ConfidenceGaugeProps {
  confidence: number | null | undefined;
  showLabel?: boolean;
  size?: 'sm' | 'md';
  className?: string;
}

export const ConfidenceGauge: FC<ConfidenceGaugeProps> = ({
  confidence,
  showLabel = true,
  size = 'md',
  className = '',
}) => {
  // Valid contract range for confidence score is 0..1
  if (
    confidence === null ||
    confidence === undefined ||
    Number.isNaN(confidence) ||
    confidence < 0 ||
    confidence > 1
  ) {
    return (
      <span className={`text-slate-500 font-mono text-xs ${className}`}>
        N/A
      </span>
    );
  }

  // Display formatting only: scale 0..1 to percentage 0..100
  const percentage = Math.round(confidence * 100);
  const barHeight = size === 'sm' ? 'h-1.5' : 'h-2';

  return (
    <div
      className={`inline-flex items-center gap-2 select-none ${className}`}
      title={`Confidence: ${percentage}% (${confidence.toFixed(3)})`}
    >
      {/* Neutral confidence visualization bar (cyan/slate, visually distinct from severity) */}
      <div
        className={`w-16 rounded-full bg-slate-800 border border-slate-700/60 overflow-hidden ${barHeight}`}
        role="progressbar"
        aria-valuenow={percentage}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Confidence score: ${percentage}%`}
      >
        <div
          className="h-full bg-cyan-500"
          style={{ width: `${percentage}%` }}
        />
      </div>

      {showLabel && (
        <span className="font-mono text-xs font-semibold text-cyan-300 min-w-[34px] text-right">
          {percentage}%
        </span>
      )}
    </div>
  );
};
