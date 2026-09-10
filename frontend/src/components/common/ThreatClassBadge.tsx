import type { FC } from 'react';
import {
  Zap,
  Radio,
  Globe,
  Lock,
  Search,
  UploadCloud,
  Shield,
} from 'lucide-react';

export interface ThreatClassBadgeProps {
  threatClass?: string | null;
  size?: 'sm' | 'md';
  className?: string;
}

function getThreatClassStyle(_threatClass: string): { borderBgText: string; iconColor: string } {
  return {
    borderBgText: 'border-slate-200 bg-slate-100 text-slate-800',
    iconColor: 'text-[#2563EB]',
  };
}

function renderThreatClassIcon(threatClass: string, iconSizes: string, iconColor: string) {
  const tc = (threatClass || '').toLowerCase();
  const cls = `${iconSizes} ${iconColor} shrink-0`;
  if (tc.includes('ddos') || tc.includes('volumetric') || tc.includes('flood')) {
    return <Zap className={cls} aria-hidden="true" />;
  }
  if (tc.includes('botnet') || tc.includes('beacon') || tc.includes('c2')) {
    return <Radio className={cls} aria-hidden="true" />;
  }
  if (tc.includes('dga') || tc.includes('dns') || tc.includes('tunnel')) {
    return <Globe className={cls} aria-hidden="true" />;
  }
  if (tc.includes('encrypted') || tc.includes('malware') || tc.includes('tls')) {
    return <Lock className={cls} aria-hidden="true" />;
  }
  if (tc.includes('recon') || tc.includes('scan') || tc.includes('port')) {
    return <Search className={cls} aria-hidden="true" />;
  }
  if (tc.includes('exfiltration') || tc.includes('data')) {
    return <UploadCloud className={cls} aria-hidden="true" />;
  }
  return <Shield className={cls} aria-hidden="true" />;
}

export const ThreatClassBadge: FC<ThreatClassBadgeProps> = ({
  threatClass,
  size = 'md',
  className = '',
}) => {
  const displayLabel = threatClass || 'N/A';
  const style = getThreatClassStyle(displayLabel);
  const sizeClasses =
    size === 'sm'
      ? 'px-2 py-0.5 text-[11px] gap-1.5'
      : 'px-2.5 py-1 text-xs gap-2';

  const iconSizes = size === 'sm' ? 'h-3 w-3' : 'h-3.5 w-3.5';

  return (
    <span
      className={`inline-flex items-center font-medium rounded-md border select-none ${style.borderBgText} ${sizeClasses} ${className}`}
      title={`Threat Class: ${displayLabel}`}
    >
      {renderThreatClassIcon(displayLabel, iconSizes, style.iconColor)}
      <span className="truncate">{displayLabel}</span>
    </span>
  );
};
