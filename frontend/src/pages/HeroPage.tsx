import { useState, useEffect, type FC } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'motion/react';
import {
  Shield,
  ArrowRight,
  Activity,
  Cpu,
  Brain,
  ChevronDown,
  CheckCircle2,
  LockKeyhole,
  Workflow,
  Radio,
  FileText,
  Lock,
  Globe,
  Network,
} from 'lucide-react';

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.3 } },
};

/** SIH 6 Core Threat Categories */
const SIH_THREAT_CLASSES = [
  {
    code: '01',
    title: 'Volumetric / Protocol DDoS',
    tag: 'Flow Rate Anomaly',
    description:
      'SYN floods, UDP reflection/amplification, and spoofed-source flood behavior detected via passive flow rates and packet inter-arrival times.',
    indicators: ['Packet rate spikes', 'Asymmetric byte ratios', 'Source IP fan-in'],
  },
  {
    code: '02',
    title: 'Botnet C2 Beaconing',
    tag: 'Periodicity Analysis',
    description:
      'Periodic C2 communication and persistent heartbeats identified through flow timing regularity and fixed inter-arrival intervals.',
    indicators: ['Fixed interval timing', 'Low-entropy flow duration', 'Persistent connection pairs'],
  },
  {
    code: '03',
    title: 'DGA / DNS Tunnelling',
    tag: 'Entropy Profiling',
    description:
      'High-entropy domain queries, long subdomain sequences, and covert data exfiltration over DNS protocol sessions.',
    indicators: ['High character entropy', 'Subdomain length anomalies', 'Query frequency spikes'],
  },
  {
    code: '04',
    title: 'Encrypted Session Malware',
    tag: 'TLS SNI & Fingerprints',
    description:
      'Malicious behavior inside TLS/QUIC sessions identified via handshake metadata, JA3/JA4 fingerprints, and packet size distributions without payload decryption.',
    indicators: ['JA3/JA4 signature match', 'Anomalous TLS SNI', 'Packet size progression'],
  },
  {
    code: '05',
    title: 'Reconnaissance / Port Scanning',
    tag: 'Host Fan-Out',
    description:
      'Network sweeps, sequential port scans, host discovery, and targeted service probing observed across unidirectional ingress flows.',
    indicators: ['Port fan-out ratio', 'Failed connection patterns', 'Sequential IP targeting'],
  },
  {
    code: '06',
    title: 'Data Exfiltration',
    tag: 'Asymmetric Transfer',
    description:
      'Unauthorized outbound data transfer and covert channels detected through asymmetric byte ratios and anomalous transfer volume.',
    indicators: ['Asymmetric flow volume', 'Long-lived session transfer', 'Unusual egress ratio'],
  },
];

/** Security Principles */
const SECURITY_PRINCIPLES = [
  {
    title: 'PASSIVE BY DESIGN',
    desc: 'Zero active packet transmission, zero return-path injection, and zero active network probing.',
    icon: <Radio className="h-5 w-5 text-[#2563EB]" />,
  },
  {
    title: 'READ-ONLY INGEST',
    desc: 'Physically & logically isolated ingest enclave. Impossible to compromise monitored networks.',
    icon: <LockKeyhole className="h-5 w-5 text-emerald-600" />,
  },
  {
    title: 'METADATA-ONLY ANALYSIS',
    desc: 'Operates entirely on IP/TCP/UDP headers, flow metrics, and TLS SNI metadata without payload decryption.',
    icon: <FileText className="h-5 w-5 text-slate-600" />,
  },
  {
    title: 'STREAMING INCREMENTAL ML',
    desc: 'Near-real-time statistical profiling and calibrated Random Forest model inference over live streams.',
    icon: <Brain className="h-5 w-5 text-[#2563EB]" />,
  },
  {
    title: 'EVIDENCE-DRIVEN TRIAGE',
    desc: 'Every threat alert is backed by quantitative feature evidence, flow context, and severity scoring.',
    icon: <Workflow className="h-5 w-5 text-amber-600" />,
  },
];

export const HeroPage: FC = () => {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mediaQuery.matches);

    const handleChange = () => setPrefersReducedMotion(mediaQuery.matches);
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-[#0A0A0A] font-sans selection:bg-blue-500/20 selection:text-blue-900">
      {/* Top Navbar */}
      <header className="sticky top-0 z-50 bg-[#F8FAFC]/90 backdrop-blur-md border-b border-[#E5E5E5]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo & SIH Context */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <div className="h-8 w-8 rounded-lg bg-[#FFFFFF] border border-[#E5E5E5] flex items-center justify-center text-[#2563EB] shadow-2xs">
                <Shield className="h-4 w-4" />
              </div>
              <span className="font-mono font-bold text-[#0A0A0A] text-base tracking-wider">
                UNITHREAT <span className="text-[#2563EB]">AI</span>
              </span>
            </div>
            <span className="hidden sm:inline-flex items-center gap-1.5 rounded-full border border-blue-200 bg-[#EFF6FF] px-2.5 py-0.5 text-[10px] font-mono font-medium text-[#2563EB]">
              <span className="h-1.5 w-1.5 rounded-full bg-[#2563EB] animate-pulse" />
              SIH 2026 · PS 26145 · NTRO
            </span>
          </div>

          {/* Desktop Nav Links */}
          <nav className="hidden md:flex items-center gap-6 text-xs font-mono text-[#525252]">
            <a href="#architecture" className="hover:text-[#2563EB] transition-colors">
              Architecture
            </a>
            <a href="#threats" className="hover:text-[#2563EB] transition-colors">
              Threat Coverage
            </a>
            <a href="#pipeline" className="hover:text-[#2563EB] transition-colors">
              Detection Pipeline
            </a>
            <a href="#principles" className="hover:text-[#2563EB] transition-colors">
              Principles
            </a>
          </nav>

          {/* Header CTA Button */}
          <Link
            to="/overview"
            className="inline-flex items-center gap-2 rounded-lg border border-transparent bg-[#2563EB] px-3.5 py-1.5 text-xs font-mono font-semibold text-white hover:bg-[#1D4ED8] transition-all shadow-2xs focus-ring"
          >
            <span>ENTER SOC CONSOLE</span>
            <ArrowRight className="h-3.5 w-3.5 text-white" />
          </Link>
        </div>
      </header>

      {/* Main Hero Section */}
      <main>
        <section className="relative pt-16 pb-20 md:pt-24 md:pb-32 overflow-hidden bg-dotted-grid border-b border-[#E5E5E5]">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <motion.div
              variants={containerVariants}
              initial="hidden"
              animate="visible"
              className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center"
            >
              {/* Left Column: Hero Text & CTAs */}
              <div className="lg:col-span-6 space-y-6">
                {/* SIH Metadata Badge */}
                <motion.div variants={itemVariants} className="inline-flex items-center gap-2">
                  <span className="inline-flex items-center gap-2 rounded-full border border-[#E5E5E5] bg-[#FFFFFF] px-3.5 py-1 text-[11px] font-mono text-[#525252] shadow-2xs">
                    <span className="h-2 w-2 rounded-full bg-[#2563EB]" />
                    <span>SIH 2026 PROBLEM STATEMENT 26145</span>
                    <span className="text-slate-300">|</span>
                    <span className="text-slate-500">NTRO CYBERSECURITY PROTOTYPE</span>
                  </span>
                </motion.div>

                {/* Primary Title */}
                <motion.h1
                  variants={itemVariants}
                  className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-[#0A0A0A] font-sans leading-[1.12] uppercase"
                >
                  AI-BASED DETECTION OF CYBER THREATS IN{' '}
                  <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#2563EB] via-blue-600 to-indigo-600">
                    UNIDIRECTIONAL IP TRAFFIC
                  </span>
                </motion.h1>

                {/* Subtitle Description */}
                <motion.p
                  variants={itemVariants}
                  className="text-base sm:text-lg text-[#525252] font-sans leading-relaxed max-w-2xl"
                >
                  UniThreat AI passively observes one-directional IP traffic and extracts behavioral
                  metadata signals to identify cyber threats without requiring a return path, active
                  probing, or payload decryption.
                </motion.p>

                {/* Architecture Badges */}
                <motion.div variants={itemVariants} className="flex flex-wrap items-center gap-2 pt-1 font-mono text-xs">
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-blue-200 bg-[#EFF6FF] px-2.5 py-1 text-[#2563EB]">
                    <CheckCircle2 className="h-3.5 w-3.5 text-[#2563EB]" />
                    PASSIVE MONITORING
                  </span>
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-200 bg-[#DCFCE7] px-2.5 py-1 text-emerald-700">
                    <Lock className="h-3.5 w-3.5 text-emerald-600" />
                    ZERO RETURN PATH
                  </span>
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-[#E5E5E5] bg-[#FFFFFF] px-2.5 py-1 text-[#0A0A0A] shadow-2xs">
                    <FileText className="h-3.5 w-3.5 text-slate-500" />
                    METADATA-ONLY
                  </span>
                  <span className="inline-flex items-center gap-1.5 rounded-md border border-[#E5E5E5] bg-[#FFFFFF] px-2.5 py-1 text-[#0A0A0A] shadow-2xs">
                    <LockKeyhole className="h-3.5 w-3.5 text-slate-500" />
                    READ-ONLY INGEST
                  </span>
                </motion.div>

                {/* Primary & Secondary Action Buttons */}
                <motion.div
                  variants={itemVariants}
                  className="flex flex-wrap items-center gap-4 pt-4"
                >
                  <Link
                    to="/overview"
                    className="inline-flex items-center gap-2.5 rounded-lg border border-transparent bg-[#2563EB] hover:bg-[#1D4ED8] px-6 py-3 text-sm font-mono font-bold text-white transition-all shadow-md focus-ring"
                  >
                    <span>ENTER SOC CONSOLE</span>
                    <ArrowRight className="h-4 w-4 text-white" />
                  </Link>

                  <a
                    href="#architecture"
                    className="inline-flex items-center gap-2 rounded-lg border border-[#E5E5E5] bg-[#FFFFFF] hover:bg-[#F5F5F5] px-5 py-3 text-sm font-mono text-[#0A0A0A] transition-colors shadow-2xs focus-ring"
                  >
                    <span>VIEW ARCHITECTURE</span>
                    <ChevronDown className="h-4 w-4 text-slate-500" />
                  </a>
                </motion.div>
              </div>

              {/* Right Column: 3D Conceptual Network Topology Visualization */}
              <motion.div variants={itemVariants} className="lg:col-span-6">
                <div className="relative w-full rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-6 shadow-sm overflow-hidden group">
                  {/* Subtle Top Spec Header */}
                  <div className="flex items-center justify-between border-b border-[#E5E5E5] pb-3 mb-5 font-mono text-xs">
                    <div className="flex items-center gap-2 text-[#0A0A0A] font-semibold">
                      <Network className="h-4 w-4 text-[#2563EB]" />
                      <span>3D UNIDIRECTIONAL TOPOLOGY MODEL</span>
                    </div>
                    <span className="text-[10px] text-[#2563EB] bg-[#EFF6FF] border border-blue-200 px-2 py-0.5 rounded-md font-mono font-bold">
                      CONCEPTUAL ARCHITECTURE
                    </span>
                  </div>

                  {/* 3D Perspective Topology Composition */}
                  <div className="relative min-h-[340px] w-full flex flex-col justify-between items-center py-2 space-y-4">
                    {/* Layer 1: Monitored Production Network Nodes */}
                    <div className="w-full rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-3 text-xs font-mono flex items-center justify-between shadow-2xs">
                      <div className="flex items-center gap-3">
                        <div className="h-7 w-7 rounded bg-[#FFFFFF] border border-[#E5E5E5] flex items-center justify-center text-[#525252]">
                          <Globe className="h-3.5 w-3.5" />
                        </div>
                        <div>
                          <div className="text-[#0A0A0A] font-semibold">PRODUCTION IP NETWORK</div>
                          <div className="text-[10px] text-[#525252] font-sans">
                            High-bandwidth operational traffic source
                          </div>
                        </div>
                      </div>
                      <span className="text-[10px] text-[#525252] bg-[#FFFFFF] border border-[#E5E5E5] px-2 py-0.5 rounded-md">
                        SOURCE
                      </span>
                    </div>

                    {/* Vector Connector Line 1 with 1-Way Particle Stream */}
                    <div className="relative h-10 w-full flex justify-center items-center">
                      <div className="h-full w-0.5 bg-gradient-to-b from-slate-300 via-blue-500 to-emerald-500" />
                      {!prefersReducedMotion && (
                        <div className="absolute top-1/4 h-2 w-2 rounded-full bg-[#2563EB] shadow-xs shadow-blue-400 animate-bounce" />
                      )}
                      <div className="absolute left-[calc(50%+16px)] whitespace-nowrap text-[10px] font-mono text-[#2563EB] flex items-center gap-1 font-semibold">
                        <span>ONE-WAY INGRESS</span>
                        <span>↓</span>
                      </div>
                    </div>

                    {/* Layer 2: Central Focal Point — Data Diode / Passive Tap Node */}
                    <div className="w-full rounded-lg border border-blue-300 bg-[#EFF6FF] p-4 text-xs font-mono flex items-center justify-between shadow-2xs relative">
                      <div className="absolute -top-2 left-6 text-[9px] font-bold text-[#2563EB] bg-[#FFFFFF] border border-blue-200 px-2 py-0.2 rounded-md uppercase tracking-wider">
                        PHYSICAL ISOLATION ENCLAVE
                      </div>
                      <div className="flex items-center gap-3 pt-1">
                        <div className="h-8 w-8 rounded bg-[#FFFFFF] border border-blue-300 flex items-center justify-center text-[#2563EB]">
                          <Lock className="h-4 w-4" />
                        </div>
                        <div>
                          <div className="text-[#1D4ED8] font-bold text-xs">
                            PASSIVE TAP / DATA DIODE
                          </div>
                          <div className="text-[10px] text-[#525252] font-sans">
                            Hardware one-way physical isolation (Zero return path)
                          </div>
                        </div>
                      </div>
                      <span className="text-[10px] font-bold text-emerald-700 bg-[#DCFCE7] border border-emerald-200 px-2 py-0.5 rounded-md">
                        ONE WAY ONLY
                      </span>
                    </div>

                    {/* Vector Connector Line 2 with 1-Way Particle Stream */}
                    <div className="relative h-10 w-full flex justify-center items-center">
                      <div className="h-full w-0.5 bg-gradient-to-b from-emerald-500 via-teal-500 to-blue-500" />
                      {!prefersReducedMotion && (
                        <div className="absolute top-2/4 h-1.5 w-1.5 rounded-full bg-emerald-500 shadow-xs shadow-emerald-400" />
                      )}
                      <div className="absolute right-[calc(50%+16px)] whitespace-nowrap text-[10px] font-mono text-emerald-700 flex items-center gap-1 font-semibold">
                        <span>↓</span>
                        <span>READ-ONLY INGEST</span>
                      </div>
                    </div>

                    {/* Layer 3: Isolated Ingest & ML Detection Pipeline Node */}
                    <div className="w-full rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-3 text-xs font-mono flex items-center justify-between shadow-2xs">
                      <div className="flex items-center gap-3">
                        <div className="h-7 w-7 rounded bg-[#FFFFFF] border border-[#E5E5E5] flex items-center justify-center text-[#2563EB]">
                          <Cpu className="h-3.5 w-3.5" />
                        </div>
                        <div>
                          <div className="text-[#0A0A0A] font-semibold">READ-ONLY INGEST & ML PIPELINE</div>
                          <div className="text-[10px] text-[#525252] font-sans">
                            Feature extraction → Statistical + ML Classifier
                          </div>
                        </div>
                      </div>
                      <span className="text-[10px] text-[#2563EB] bg-[#EFF6FF] border border-blue-200 px-2 py-0.5 rounded-md font-semibold">
                        INFERENCE
                      </span>
                    </div>

                    {/* Vector Connector Line 3 */}
                    <div className="h-6 w-0.5 bg-slate-300" />

                    {/* Layer 4: SOC Operational Console Node */}
                    <div className="w-full rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-3 text-xs font-mono flex items-center justify-between shadow-2xs">
                      <div className="flex items-center gap-3">
                        <div className="h-7 w-7 rounded bg-[#FFFFFF] border border-[#E5E5E5] flex items-center justify-center text-[#525252]">
                          <Activity className="h-3.5 w-3.5" />
                        </div>
                        <div>
                          <div className="text-[#0A0A0A] font-semibold">SOC OPERATIONAL CONSOLE</div>
                          <div className="text-[10px] text-[#525252] font-sans">
                            Analyst threat triage & evidence inspection
                          </div>
                        </div>
                      </div>
                      <span className="text-[10px] text-[#525252] bg-[#FFFFFF] border border-[#E5E5E5] px-2 py-0.5 rounded-md">
                        OUTPUT
                      </span>
                    </div>
                  </div>

                  {/* Architecture Guarantee Note */}
                  <div className="mt-4 rounded-lg border border-[#E5E5E5] bg-[#F8FAFC] p-3 text-[11px] font-mono text-[#525252] space-y-1">
                    <div className="text-[#0A0A0A] font-semibold flex items-center gap-1.5 text-[11px]">
                      <LockKeyhole className="h-3.5 w-3.5 text-[#2563EB]" />
                      ZERO RETURN PATH GUARANTEE:
                    </div>
                    <p className="font-sans text-[#525252] text-[11px]">
                      The system is physically and logically incapable of injecting packets, performing return-path handshakes, or transmitting signals back into the monitored network.
                    </p>
                  </div>
                </div>
              </motion.div>
            </motion.div>
          </div>
        </section>

        {/* Section 1: Unidirectional Architecture (`#architecture`) */}
        <section id="architecture" className="py-20 border-b border-[#E5E5E5] bg-[#F8FAFC]">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
            <div className="text-center max-w-3xl mx-auto space-y-3">
              <span className="text-xs font-mono text-[#2563EB] uppercase tracking-widest font-semibold">
                SYSTEM ARCHITECTURE
              </span>
              <h2 className="text-2xl sm:text-3xl font-bold font-sans text-[#0A0A0A] uppercase">
                UNIDIRECTIONAL DATA DIODE ARCHITECTURE
              </h2>
              <p className="text-xs sm:text-sm font-sans text-[#525252]">
                Strict physical & logical one-way isolation ensures zero risk to monitored operational networks.
              </p>
            </div>

            {/* Architecture Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-sans">
              <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-6 space-y-3 shadow-2xs hover:border-[#D4D4D4] transition-all">
                <div className="h-10 w-10 rounded-lg bg-[#EFF6FF] border border-blue-200 flex items-center justify-center text-[#2563EB]">
                  <Radio className="h-5 w-5" />
                </div>
                <h3 className="text-base font-bold font-sans text-[#0A0A0A] uppercase">
                  Passive Observation
                </h3>
                <p className="text-xs text-[#525252] leading-relaxed">
                  Traffic is copied passively using an optical splitter or data diode mirror port. The detector never sits inline on the active communications path.
                </p>
              </div>

              <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-6 space-y-3 shadow-2xs hover:border-[#D4D4D4] transition-all">
                <div className="h-10 w-10 rounded-lg bg-[#DCFCE7] border border-emerald-200 flex items-center justify-center text-emerald-600">
                  <Lock className="h-5 w-5" />
                </div>
                <h3 className="text-base font-bold font-sans text-[#0A0A0A] uppercase">
                  Zero Return Path
                </h3>
                <p className="text-xs text-[#525252] leading-relaxed">
                  No return-path drivers, packet injection modules, or active probing mechanisms exist. The detector cannot send signals back to the target network.
                </p>
              </div>

              <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-6 space-y-3 shadow-2xs hover:border-[#D4D4D4] transition-all">
                <div className="h-10 w-10 rounded-lg bg-[#F8FAFC] border border-[#E5E5E5] flex items-center justify-center text-slate-600">
                  <FileText className="h-5 w-5" />
                </div>
                <h3 className="text-base font-bold font-sans text-[#0A0A0A] uppercase">
                  Metadata-Only Inspection
                </h3>
                <p className="text-xs text-[#525252] leading-relaxed">
                  Feature extraction relies entirely on IP/TCP/UDP packet headers, flow statistics, and TLS SNI metadata without payload decryption.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Section 2: SIH Threat Detection Coverage (`#threats`) */}
        <section id="threats" className="py-20 border-b border-[#E5E5E5] bg-dotted-grid">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
            <div className="text-center max-w-3xl mx-auto space-y-3">
              <span className="text-xs font-mono text-[#2563EB] uppercase tracking-widest font-semibold">
                PROBLEM STATEMENT 26145
              </span>
              <h2 className="text-2xl sm:text-3xl font-bold font-sans text-[#0A0A0A] uppercase">
                SIH THREAT DETECTION COVERAGE
              </h2>
              <p className="text-xs sm:text-sm font-sans text-[#525252]">
                Authoritative coverage across the six core cyber threat categories specified in the SIH problem statement.
              </p>
            </div>

            {/* 6 Threat Class Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 font-sans">
              {SIH_THREAT_CLASSES.map((item) => (
                <div
                  key={item.code}
                  className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-6 space-y-4 shadow-2xs hover:border-[#D4D4D4] transition-all flex flex-col justify-between"
                >
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-[#2563EB] bg-[#EFF6FF] border border-blue-200 px-2 py-0.5 rounded-md">
                        {item.code}
                      </span>
                      <span className="font-mono text-[11px] text-[#525252] bg-[#F8FAFC] border border-[#E5E5E5] px-2 py-0.5 rounded-md">
                        {item.tag}
                      </span>
                    </div>

                    <h3 className="text-sm font-bold font-sans text-[#0A0A0A] uppercase tracking-wider">
                      {item.title}
                    </h3>

                    <p className="text-xs text-[#525252] leading-relaxed">{item.description}</p>
                  </div>

                  <div className="pt-3 border-t border-[#E5E5E5] space-y-1.5">
                    <div className="text-[10px] font-mono text-slate-500 uppercase">Key Indicators:</div>
                    <ul className="space-y-1">
                      {item.indicators.map((ind) => (
                        <li
                          key={ind}
                          className="text-[11px] font-mono text-[#525252] flex items-center gap-1.5"
                        >
                          <span className="h-1 w-1 rounded-full bg-[#2563EB]" />
                          <span>{ind}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Section 3: Metadata-Only Encrypted Traffic Analysis */}
        <section className="py-20 border-b border-[#E5E5E5] bg-[#F8FAFC]">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
              <div className="lg:col-span-6 space-y-4">
                <span className="text-xs font-mono text-[#2563EB] uppercase tracking-widest font-semibold">
                  CRYPTOGRAPHIC PRIVACY COMPLIANCE
                </span>
                <h2 className="text-2xl sm:text-3xl font-bold font-sans text-[#0A0A0A] uppercase leading-tight">
                  ENCRYPTED TRAFFIC ANALYSIS WITHOUT DECRYPTION
                </h2>
                <p className="text-xs sm:text-sm text-[#525252] leading-relaxed font-sans">
                  TLS and QUIC encrypted sessions are analyzed using observable metadata signatures—such as JA3/JA4 fingerprints, packet length sequences, and inter-arrival timing—without decrypting payload content or violating privacy boundaries.
                </p>
                <div className="pt-2">
                  <div className="rounded-xl border border-blue-200 bg-[#EFF6FF] p-4 text-xs font-mono text-[#2563EB] space-y-1">
                    <div className="font-semibold text-[#1D4ED8] uppercase">
                      NO DECRYPTION REQUIRED
                    </div>
                    <p className="font-sans text-[#525252] text-xs leading-relaxed">
                      Detects malicious encrypted sessions using statistical behavior & handshake parameters while leaving session keys and payloads completely untouched.
                    </p>
                  </div>
                </div>
              </div>

              <div className="lg:col-span-6 grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
                <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 space-y-2 shadow-2xs">
                  <div className="text-[#2563EB] font-bold">01 · JA3/JA4 FINGERPRINTS</div>
                  <div className="text-[#525252] text-[11px] font-sans">
                    Client & server TLS cipher suite and extension negotiation signatures.
                  </div>
                </div>

                <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 space-y-2 shadow-2xs">
                  <div className="text-emerald-600 font-bold">02 · INTER-ARRIVAL TIME (IAT)</div>
                  <div className="text-[#525252] text-[11px] font-sans">
                    Packet timing distributions revealing automated C2 beaconing.
                  </div>
                </div>

                <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 space-y-2 shadow-2xs">
                  <div className="text-[#0A0A0A] font-bold">03 · PACKET LENGTH SEQUENCES</div>
                  <div className="text-[#525252] text-[11px] font-sans">
                    Payload size progression patterns characterising specific malware types.
                  </div>
                </div>

                <div className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 space-y-2 shadow-2xs">
                  <div className="text-[#2563EB] font-bold">04 · SNI & CERT METADATA</div>
                  <div className="text-[#525252] text-[11px] font-sans">
                    Server Name Indication domains and certificate validation state.
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Section 4: Detection Pipeline (`#pipeline`) */}
        <section id="pipeline" className="py-20 border-b border-[#E5E5E5] bg-dotted-grid">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
            <div className="text-center max-w-3xl mx-auto space-y-3">
              <span className="text-xs font-mono text-[#2563EB] uppercase tracking-widest font-semibold">
                END-TO-END WORKFLOW
              </span>
              <h2 className="text-2xl sm:text-3xl font-bold font-sans text-[#0A0A0A] uppercase">
                DETECTION PIPELINE FLOW
              </h2>
              <p className="text-xs sm:text-sm font-sans text-[#525252]">
                From passive optical TAP ingest to SOC analyst evidence triage.
              </p>
            </div>

            {/* Pipeline Horizontal Flow Steps */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4 font-mono text-xs">
              {[
                { step: '01', title: 'PASSIVE INGEST', desc: 'Optical TAP / Data Diode mirror stream' },
                { step: '02', title: 'FEATURE EXTRACTION', desc: 'Flow profiling & statistical metrics' },
                { step: '03', title: 'STATISTICAL ENGINE', desc: 'Baseline anomaly detection' },
                { step: '04', title: 'ML INFERENCE', desc: 'Calibrated Threat Classifier model' },
                { step: '05', title: 'EVIDENCE SIGNALS', desc: 'Quantitative feature breakdown' },
                { step: '06', title: 'SOC VISUALIZATION', desc: 'Analyst triage & monitoring' },
              ].map((s) => (
                <div
                  key={s.step}
                  className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-4 space-y-2 text-center flex flex-col justify-between shadow-2xs"
                >
                  <div className="space-y-1.5">
                    <span className="inline-block text-xs font-bold text-[#2563EB] bg-[#EFF6FF] border border-blue-200 px-2 py-0.5 rounded-md">
                      STEP {s.step}
                    </span>
                    <div className="font-bold text-[#0A0A0A] uppercase text-[11px] tracking-wider">
                      {s.title}
                    </div>
                  </div>
                  <div className="text-[10px] text-[#525252] font-sans pt-1 border-t border-[#E5E5E5]">
                    {s.desc}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Section 5: Security Principles (`#principles`) */}
        <section id="principles" className="py-20 border-b border-[#E5E5E5] bg-[#F8FAFC]">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
            <div className="text-center max-w-3xl mx-auto space-y-3">
              <span className="text-xs font-mono text-[#2563EB] uppercase tracking-widest font-semibold">
                ARCHITECTURAL GUARANTEES
              </span>
              <h2 className="text-2xl sm:text-3xl font-bold font-sans text-[#0A0A0A] uppercase">
                CORE SECURITY PRINCIPLES
              </h2>
              <p className="text-xs sm:text-sm font-sans text-[#525252]">
                Engineered for sovereign defense, OT/ICS networks, and critical national infrastructure.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 font-sans text-xs">
              {SECURITY_PRINCIPLES.map((p) => (
                <div
                  key={p.title}
                  className="rounded-xl border border-[#E5E5E5] bg-[#FFFFFF] p-5 space-y-3 shadow-2xs hover:border-[#D4D4D4] transition-all flex flex-col justify-between"
                >
                  <div className="space-y-2">
                    <div className="h-9 w-9 rounded-lg bg-[#F8FAFC] border border-[#E5E5E5] flex items-center justify-center">
                      {p.icon}
                    </div>
                    <h3 className="font-bold font-mono text-[#0A0A0A] uppercase text-xs">
                      {p.title}
                    </h3>
                  </div>
                  <p className="text-[#525252] text-[11px] leading-relaxed">{p.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Bottom CTA Banner */}
        <section className="py-24 bg-dotted-grid border-t border-[#E5E5E5]">
          <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center space-y-6">
            <div className="inline-flex items-center gap-2 rounded-full border border-blue-200 bg-[#EFF6FF] px-3 py-1 text-xs font-mono text-[#2563EB]">
              <span className="h-2 w-2 rounded-full bg-[#2563EB] animate-pulse" />
              OPERATIONAL CONSOLE READY
            </div>

            <h2 className="text-3xl sm:text-4xl font-bold font-sans text-[#0A0A0A] uppercase tracking-tight">
              READY TO EXPLORE THE SOC CONSOLE?
            </h2>

            <p className="text-base text-[#525252] font-sans max-w-xl mx-auto leading-relaxed">
              Access passive threat intelligence, flow metrics, ML predictions, and alert triage inside the UniThreat AI SOC Command Center.
            </p>

            <div className="pt-2">
              <Link
                to="/overview"
                className="inline-flex items-center gap-3 rounded-lg border border-transparent bg-[#2563EB] hover:bg-[#1D4ED8] px-8 py-3.5 text-base font-mono font-bold text-white transition-all shadow-md focus-ring"
              >
                <span>ENTER SOC CONSOLE</span>
                <ArrowRight className="h-5 w-5 text-white" />
              </Link>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#E5E5E5] bg-[#FFFFFF] py-8 text-xs font-mono text-[#525252]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="space-y-1 text-center md:text-left">
            <div className="font-bold text-[#0A0A0A]">
              UNITHREAT <span className="text-[#2563EB]">AI</span>
            </div>
            <div className="text-[11px] text-[#525252] font-sans">
              AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
            </div>
          </div>

          <div className="text-center text-[11px] text-[#525252] space-y-1">
            <div>SIH 2026 · PROBLEM STATEMENT 26145</div>
            <div className="text-[#0A0A0A] font-semibold">NATIONAL TECHNICAL RESEARCH ORGANISATION (NTRO)</div>
          </div>

          <div className="flex items-center gap-2 text-[10px] text-[#2563EB]">
            <span className="border border-blue-200 bg-[#EFF6FF] px-2 py-0.5 rounded-md font-semibold">PASSIVE</span>
            <span className="border border-emerald-200 bg-[#DCFCE7] text-emerald-700 px-2 py-0.5 rounded-md font-semibold">READ-ONLY</span>
            <span className="border border-[#E5E5E5] bg-[#F8FAFC] text-[#525252] px-2 py-0.5 rounded-md">METADATA-ONLY</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
