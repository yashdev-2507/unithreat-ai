import type { FC } from 'react';
import { Cpu, CheckCircle2 } from 'lucide-react';
import type { MlPrediction } from '../../types/ml';
import { ThreatClassBadge } from '../common/ThreatClassBadge';
import { ConfidenceGauge } from '../common/ConfidenceGauge';

export interface MlPredictionsPanelProps {
  predictions: MlPrediction[];
}

export const MlPredictionsPanel: FC<MlPredictionsPanelProps> = ({ predictions }) => {
  if (!predictions || predictions.length === 0) {
    return (
      <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2 border-b border-[var(--panel-border-subtle)] pb-3">
          <Cpu className="h-4 w-4 text-cyan-400" />
          Backend ML Model Predictions
        </h3>
        <p className="py-4 text-center text-xs text-slate-400 font-sans">
          No ML model predictions generated for this flow.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-[var(--panel-border)] bg-[var(--panel-bg)] p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-[var(--panel-border-subtle)] pb-3">
        <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono flex items-center gap-2">
          <Cpu className="h-4 w-4 text-cyan-400" />
          Backend ML Model Predictions ({predictions.length})
        </h3>
        <span className="text-xs text-slate-400 font-mono">Inference Output</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
        {predictions.map((pred, idx) => (
          <div
            key={`${pred.flow_id}-${pred.model_version}-${idx}`}
            className="rounded-lg border border-slate-800 bg-slate-900/40 p-4 space-y-3"
          >
            <div className="flex items-center justify-between">
              <ThreatClassBadge threatClass={pred.threat_class} size="sm" />
              {pred.calibrated !== undefined && (
                <span
                  className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-mono border ${
                    pred.calibrated
                      ? 'border-emerald-800/50 bg-emerald-950/30 text-emerald-300'
                      : 'border-slate-700 bg-slate-800 text-slate-400'
                  }`}
                >
                  {pred.calibrated && <CheckCircle2 className="h-3 w-3" />}
                  {pred.calibrated ? 'Calibrated' : 'Uncalibrated'}
                </span>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3 pt-1">
              <div>
                <span className="text-slate-400 block text-[11px] font-sans">Prediction Score</span>
                <div className="mt-1">
                  <ConfidenceGauge confidence={pred.score} size="md" />
                </div>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px] font-sans">Model Version</span>
                <span className="text-slate-200 font-bold mt-1 block flex items-center gap-1">
                  <Cpu className="h-3 w-3 text-slate-400" />
                  {pred.model_version}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
