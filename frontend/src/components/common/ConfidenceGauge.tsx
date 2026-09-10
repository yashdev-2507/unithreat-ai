import type { FC } from 'react';
import { SeverityBadge } from './SeverityBadge';
import type { SeverityLevel } from '../../types';

export interface ConfidenceGaugeProps {
  confidence: number | null | undefined;
  showLabel?: boolean;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'bar' | 'ring';
  severity?: string;
  className?: string;
}

export const ConfidenceGauge: FC<ConfidenceGaugeProps> = ({
  confidence,
  showLabel = true,
  size = 'md',
  variant = 'bar',
  severity,
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
      <span className={`text-slate-400 font-mono text-xs ${className}`}>
        N/A
      </span>
    );
  }

  // Display formatting only: scale 0..1 to percentage 0..100
  const percentage = Math.round(confidence * 100);

  if (variant === 'ring') {
    // Ring Variant for Featured Alert Panel (Reference-Inspired)
    const r = 42;
    const strokeWidth = 7;
    const C = 2 * Math.PI * r; // ~263.893
    const dashoffset = C * (1 - confidence);

    let ringStroke = '#2563EB';
    let trackStroke = '#DBEAFE';
    if (severity === 'CRITICAL') {
      ringStroke = '#DC2626';
      trackStroke = '#FEE2E2';
    } else if (severity === 'HIGH') {
      ringStroke = '#EA580C';
      trackStroke = '#FFEDD5';
    } else if (severity === 'MEDIUM') {
      ringStroke = '#D97706';
      trackStroke = '#FEF3C7';
    }

    return (
      <div className={`relative flex flex-col items-center justify-center select-none ${className}`}>
        <div className="relative w-56 h-56 sm:w-64 sm:h-64 flex items-center justify-center">
          <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
            {/* Background Circle Track */}
            <circle
              cx="50"
              cy="50"
              r={r}
              fill="transparent"
              stroke={trackStroke}
              strokeWidth={strokeWidth}
            />
            {/* Foreground Animated Confidence Circle */}
            <circle
              cx="50"
              cy="50"
              r={r}
              fill="transparent"
              stroke={ringStroke}
              strokeWidth={strokeWidth}
              strokeDasharray={C}
              strokeDashoffset={dashoffset}
              strokeLinecap="round"
              className="transition-all duration-700 ease-out"
            />
          </svg>

          {/* Inner Content */}
          <div className="absolute inset-0 flex flex-col items-center justify-center text-center p-4 space-y-1">
            <span className="text-[11px] font-mono text-slate-500 uppercase tracking-widest font-semibold">
              CONFIDENCE
            </span>
            <span className="text-4xl sm:text-5xl font-extrabold font-mono text-[#0A0A0A] tracking-tight">
              {percentage}%
            </span>
            {severity && (
              <div className="pt-1">
                <SeverityBadge severity={severity as SeverityLevel} size="sm" />
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // Standard Linear Bar Variant (Default)
  const barHeight = size === 'sm' ? 'h-1.5' : 'h-2';
  const barWidth = size === 'sm' ? 'w-14' : 'w-20';

  // Multi-tier color coding for light theme
  let barColor = 'bg-[#2563EB]';
  let textColor = 'text-[#0A0A0A]';
  if (confidence < 0.5) {
    barColor = 'bg-slate-400';
    textColor = 'text-slate-600';
  } else if (confidence < 0.8) {
    barColor = 'bg-blue-500';
    textColor = 'text-slate-800';
  }

  return (
    <div
      className={`inline-flex items-center gap-2 select-none ${className}`}
      title={`Confidence: ${percentage}% (${confidence.toFixed(3)})`}
    >
      {/* Neutral confidence visualization bar */}
      <div
        className={`${barWidth} rounded-full bg-slate-100 border border-slate-200 overflow-hidden ${barHeight}`}
        role="progressbar"
        aria-valuenow={percentage}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Confidence score: ${percentage}%`}
      >
        <div
          className={`h-full transition-all duration-300 ease-out ${barColor}`}
          style={{ width: `${percentage}%` }}
        />
      </div>

      {showLabel && (
        <span className={`font-mono text-xs font-semibold ${textColor} min-w-[34px] text-right`}>
          {percentage}%
        </span>
      )}
    </div>
  );
};
