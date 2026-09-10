import type { FC } from 'react';
import { Shield, Globe, Lock, Cpu } from 'lucide-react';
import type { PassiveFlow } from '../../types/flow';

export interface ProtocolMetadataPanelProps {
  flow: PassiveFlow;
}

export const ProtocolMetadataPanel: FC<ProtocolMetadataPanelProps> = ({ flow }) => {
  const hasDns = Boolean(flow.dns && Object.keys(flow.dns).length > 0);
  const hasTls = Boolean(flow.tls && Object.keys(flow.tls).length > 0);
  const hasQuic = Boolean(flow.quic && Object.keys(flow.quic).length > 0);

  if (!hasDns && !hasTls && !hasQuic) {
    return (
      <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-3 shadow-2xs">
        <h3 className="text-base font-bold text-[#0A0A0A] font-sans flex items-center gap-2 border-b border-[#E5E5E5] pb-3">
          <Shield className="h-4 w-4 text-[#2563EB]" />
          Passive Protocol Metadata
        </h3>
        <p className="py-4 text-center text-xs text-[#525252] font-sans">
          No passive DNS, TLS, or QUIC metadata attached to this flow.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-5 shadow-2xs">
      <h3 className="text-base font-bold text-[#0A0A0A] font-sans flex items-center gap-2 border-b border-[#E5E5E5] pb-3">
        <Shield className="h-4 w-4 text-[#2563EB]" />
        Passive Protocol Metadata
      </h3>

      <div className="space-y-4">
        {/* Passive DNS Metadata */}
        {hasDns && flow.dns && (
          <div className="rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-4 space-y-3">
            <h4 className="text-xs font-bold text-[#2563EB] uppercase tracking-wider font-sans flex items-center gap-2">
              <Globe className="h-3.5 w-3.5 text-[#2563EB]" />
              Passive DNS Metadata
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
              <div>
                <span className="text-slate-500 block text-[11px] font-sans">Query Name</span>
                <span className="text-[#0A0A0A] font-medium break-all">
                  {String(flow.dns.query_name || 'N/A')}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px] font-sans">Query Type</span>
                <span className="text-[#0A0A0A] font-medium">
                  {String(flow.dns.query_type || 'N/A')}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px] font-sans">Response Code</span>
                <span className="text-[#0A0A0A] font-medium">
                  {String(flow.dns.response_code || 'N/A')}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Passive TLS Metadata */}
        {hasTls && flow.tls && (
          <div className="rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-4 space-y-3">
            <h4 className="text-xs font-bold text-[#2563EB] uppercase tracking-wider font-mono flex items-center gap-2">
              <Lock className="h-3.5 w-3.5 text-[#2563EB]" />
              Passive TLS Metadata
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
              <div>
                <span className="text-slate-500 block text-[11px] font-sans">SNI</span>
                <span className="text-[#2563EB] font-medium break-all">
                  {String(flow.tls.sni || 'N/A')}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px] font-sans">JA3 Fingerprint</span>
                <span className="text-[#0A0A0A] font-medium break-all">
                  {String(flow.tls.ja3 || 'N/A')}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px] font-sans">TLS Version</span>
                <span className="text-[#0A0A0A] font-medium">
                  {String(flow.tls.version || 'N/A')}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px] font-sans">Cipher Suite</span>
                <span className="text-[#0A0A0A] font-medium break-all">
                  {String(flow.tls.cipher_suite || 'N/A')}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Passive QUIC Metadata */}
        {hasQuic && flow.quic && (
          <div className="rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-4 space-y-3">
            <h4 className="text-xs font-bold text-[#2563EB] uppercase tracking-wider font-mono flex items-center gap-2">
              <Cpu className="h-3.5 w-3.5 text-[#2563EB]" />
              Passive QUIC Metadata
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
              <div>
                <span className="text-slate-500 block text-[11px] font-sans">SNI</span>
                <span className="text-[#2563EB] font-medium break-all">
                  {String(flow.quic.sni || 'N/A')}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px] font-sans">QUIC Version</span>
                <span className="text-[#0A0A0A] font-medium">
                  {String(flow.quic.version || 'N/A')}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[11px] font-sans">Cipher</span>
                <span className="text-[#0A0A0A] font-medium break-all">
                  {String(flow.quic.cipher || 'N/A')}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
