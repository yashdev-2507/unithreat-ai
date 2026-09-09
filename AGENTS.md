# UniThreat AI — Agent Guidelines

## 1. Project Context

UniThreat AI is the frontend of the SIH 2026 project for Problem
Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional
IP Traffic.

The frontend is an analyst-facing visualization and interaction layer
for a passive cybersecurity detection pipeline.

---

## 2. ABSOLUTE RULE — BACKEND DATA FIRST

Build the frontend around backend-provided data.

NEVER build or invent backend data to satisfy the frontend design.

The backend is responsible for:
- traffic analysis
- feature extraction
- statistical detection
- ML inference
- threat classification
- severity
- confidence
- evidence
- security intelligence
- backend telemetry

The frontend is responsible for:
- consuming backend data
- displaying backend data
- visualizing backend data
- filtering, searching and sorting backend data
- navigating between backend-provided records
- handling loading, empty, error and unavailable states

The frontend must NOT independently create cybersecurity
intelligence.

---

## 3. NO FRONTEND DETECTION LOGIC

Never implement cybersecurity detection or inference in the frontend.

Do not calculate or infer:
- DDoS
- SYN/UDP flood detection
- botnet beaconing
- DGA
- DNS tunnelling
- encrypted malware
- reconnaissance
- port scanning
- data exfiltration
- threat scores
- severity
- confidence
- evidence
- threat correlations
- attack relationships

These values must come from the backend.

Frontend calculations are allowed only for presentation purposes,
such as formatting, sorting, pagination, and chart rendering.

---

## 4. CONTRACTS ARE THE SOURCE OF TRUTH

The `contracts/` directory is authoritative.

Current contracts:
- `contracts/alert-schema.json`
- `contracts/evidence-schema.json`
- `contracts/flow-schema.json`
- `contracts/feature-schema.json`
- `contracts/ml-prediction-schema.json`

Contract-backed TypeScript types and mock data must conform to these
schemas.

Do not modify contract files unless explicitly instructed.

Do not add frontend-only fields to contract-backed objects.

If required information is not defined by the contracts/API, identify
it as:

`BACKEND/API REQUIREMENT — NOT CURRENTLY DEFINED`

Do not fabricate it.

---

## 5. NO INVENTED INTELLIGENCE

Never invent:
- explanations
- attack reasons
- risk scores
- feature importance
- attack chains
- correlations
- source/destination reputation
- malware families
- MITRE mappings
- geographic intelligence
- threat-intelligence enrichment

unless explicitly supplied by the backend/API.

The frontend must remain technically honest about what the backend
actually provides.

---

## 6. FRONTEND / BACKEND BOUNDARY

Architecture:

Backend
  ↓
Contracts / REST / WebSocket / SSE
  ↓
DataService
  ↓
React UI

The UI must not depend directly on mock implementations or backend
transport details.

Use a lightweight DataService abstraction so mock data can later be
replaced with the real backend with minimal UI changes.

Do not introduce unnecessary enterprise architecture.

---

## 7. APPROVED FRONTEND STACK

Production frontend:

- React
- TypeScript
- Vite
- Tailwind CSS
- shadcn/ui
- Lucide React
- Recharts
- Motion
- React Router
- React hooks/local state
- REST API integration
- WebSocket or SSE for realtime data

Do not introduce Redux, Zustand, dependency-injection frameworks,
event buses, or other unnecessary abstractions unless a real
requirement exists.

---

## 8. DESIGN SYSTEM

The frontend must use one consistent UniThreat AI design system.

Visual direction:

**Professional Dark SOC/NOC Operations Console**

The interface should be:
- dark-first
- information-dense but readable
- technically precise
- high contrast
- compact
- consistent
- operational rather than decorative

Use:
- restrained borders
- moderate corner radius
- consistent spacing
- meaningful tables
- meaningful charts
- clear status indicators
- strong visual hierarchy

Avoid:
- excessive gradients
- neon cyberpunk styling
- excessive glassmorphism
- excessive glow
- giant hero sections
- huge rounded cards
- decorative illustrations
- excessive animation
- random colors
- oversized typography
- repeated "AI-powered" marketing labels

---

## 9. DESIGN TOKENS

Use semantic design tokens rather than scattered hardcoded colors.

Security severity:

- Critical → red/rose
- High → orange
- Medium → amber
- Low → subdued neutral/slate

Operational status:

- Healthy → green
- Warning → amber
- Error → red
- Informational → restrained blue/cyan

Do not rely on color alone to communicate important states.

---

## 10. UI COMPONENTS

Use shadcn/ui where appropriate and create reusable components for
repeated UniThreat patterns.

Examples:
- MetricCard
- SeverityBadge
- ThreatClassBadge
- ConfidenceGauge
- PipelineStatusIndicator
- EvidenceSignal
- AlertTable
- FlowTable
- FlowDetailInspector
- AlertDetailPanel
- RealtimeIndicator
- LoadingState
- EmptyState
- ErrorState
- NullState

Do not create abstractions without a practical reason.

---

## 11. UI/UX PRO MAX

UI/UX Pro Max is used as design intelligence/reference.

Use it to inform:
- visual hierarchy
- typography
- spacing
- component patterns
- dashboard composition
- UX patterns
- accessibility
- responsive behavior
- information density
- interaction design
- visual consistency

Adapt recommendations specifically to UniThreat AI.

UI/UX Pro Max does NOT define backend data or application logic and
must never override the backend-data-first rule.

It is not a required production frontend dependency.

---

## 12. V0 / 21ST.DEV

v0 and 21st.dev are visual reference and inspiration sources.

They may be used to:
- explore layouts
- compare component approaches
- improve visual polish
- refine UI patterns

They are not the source of truth for:
- backend architecture
- contracts
- API schemas
- security logic
- application data

Do not blindly copy generated code.

Production code must follow this project's architecture and stack.

---

## 13. PASSIVE / READ-ONLY REQUIREMENT

The system is strictly passive and read-only.

The frontend must never imply or implement:
- active probing
- return-path communication
- packet injection
- automated blocking
- mitigation commands
- handshake completion
- payload decryption

TLS/QUIC information must remain metadata-only.

---

## 14. REALTIME

Realtime data may use WebSocket or SSE.

Support clear states such as:
- LIVE
- REPLAY
- CONNECTED
- DISCONNECTED
- PROCESSING
- DEGRADED

Use animation only when it communicates state or improves usability.

For high-volume streams, use bounded buffering and appropriate
rendering strategies when actually required.

Do not hardcode throughput or performance claims.

---

## 15. DATA AVAILABILITY

Every data-driven UI must handle:
- loading
- empty
- error
- unavailable
- disconnected
- no data
- ML unavailable

Never fabricate data to make the interface appear complete.

---

## 16. ACCESSIBILITY

Use:
- semantic HTML
- keyboard navigation
- visible focus states
- accessible labels
- sufficient contrast

Important states must use text/icons in addition to color.

---

## 17. GIT AND FILE SAFETY

Do not:
- modify backend code
- modify contracts without explicit approval
- overwrite unrelated work
- reset or delete existing work
- make broad repository changes for a frontend task

Keep frontend changes inside the frontend scope unless explicitly
approved otherwise.

Before making significant changes, inspect the existing repository
and understand the current implementation.

---

## 18. IMPLEMENTATION PRINCIPLE

Always follow this priority:

1. Backend contracts and actual backend data
2. SIH problem requirements
3. Frontend architecture
4. Usability
5. Design system
6. Visual polish

Never sacrifice contract correctness or backend compatibility for
visual appearance.

**BACKEND DATA FIRST. UI SECOND.**

When uncertain whether something is backend-provided or should be
invented by the frontend, stop and identify it as a backend/API
requirement rather than assuming.
