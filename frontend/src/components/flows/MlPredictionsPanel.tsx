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
      <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-3 shadow-2xs">
        <h3 className="text-base font-bold text-[#0A0A0A] font-sans flex items-center gap-2 border-b border-[#E5E5E5] pb-3">
          <Cpu className="h-4 w-4 text-[#2563EB]" />
          Backend ML Model Predictions
        </h3>
        <p className="py-4 text-center text-xs text-[#525252] font-sans">
          No ML model predictions generated for this flow.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-4 shadow-2xs">
      <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3">
        <h3 className="text-base font-bold text-[#0A0A0A] font-sans flex items-center gap-2">
          <Cpu className="h-4 w-4 text-[#2563EB]" />
          Backend ML Model Predictions ({predictions.length})
        </h3>
        <span className="text-xs text-slate-500 font-mono">Inference Output</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
        {predictions.map((pred, idx) => (
          <div
            key={`${pred.flow_id}-${pred.model_version}-${idx}`}
            className="rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-4 space-y-3"
          >
            <div className="flex items-center justify-between">
              <ThreatClassBadge threatClass={pred.threat_class} size="sm" />
              {pred.calibrated !== undefined && (
                <span
                  className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-mono border ${
                    pred.calibrated
                      ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
                      : 'border-slate-200 bg-slate-100 text-slate-600'
                  }`}
                >
                  {pred.calibrated && <CheckCircle2 className="h-3 w-3" />}
                  {pred.calibrated ? 'Calibrated' : 'Uncalibrated'}
                </span>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3 pt-1">
              <div>
                <span className="text-slate-500 block text-[11px] font-sans">Prediction Score</span>
                <div className="mt-1">
                  <ConfidenceGauge confidence={pred.score} size="md" />
                </div>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px] font-sans">Model Version</span>
                <span className="text-[#0A0A0A] font-bold mt-1 block flex items-center gap-1">
                  <Cpu className="h-3 w-3 text-slate-500" />
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
