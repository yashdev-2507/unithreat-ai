import type { FC } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AppShell } from '../components/layout/AppShell';
import { HeroPage } from '../pages/HeroPage';
import { OverviewPage } from '../pages/OverviewPage';
import { AlertsPage } from '../pages/AlertsPage';
import { FlowsPage } from '../pages/FlowsPage';
import { FlowInvestigationPage } from '../pages/FlowInvestigationPage';
import { ThreatAnalysisPage } from '../pages/ThreatAnalysisPage';
import { DetectionAnalyticsPage } from '../pages/DetectionAnalyticsPage';
import { MlIntelligencePage } from '../pages/MlIntelligencePage';
import { SystemMonitoringPage } from '../pages/SystemMonitoringPage';
import type { DataService } from '../services/DataService';
import { defaultDataService } from '../services';

export interface AppRoutesProps {
  dataService?: DataService;
}

export const AppRoutes: FC<AppRoutesProps> = ({ dataService = defaultDataService }) => {
  return (
    <Routes>
      <Route path="/" element={<AppShell dataService={dataService} />}>
        {/* Redirect root path to /overview */}
        <Route index element={<Navigate to="/overview" replace />} />

      {/* Operational Console Routes (Wrapped in AppShell with Sidebar & Header) */}
      <Route element={<AppShell />}>
        {/* 7 Primary Navigation Views */}
        <Route path="overview" element={<OverviewPage dataService={dataService} />} />
        <Route path="alerts" element={<AlertsPage dataService={dataService} />} />
        <Route path="flows" element={<FlowsPage dataService={dataService} />} />
        <Route
          path="threat-analysis"
          element={<ThreatAnalysisPage dataService={dataService} />}
        />
        <Route
          path="analytics"
          element={<DetectionAnalyticsPage dataService={dataService} />}
        />
        <Route
          path="ml-intelligence"
          element={<MlIntelligencePage dataService={dataService} />}
        />
        <Route
          path="system-health"
          element={<SystemMonitoringPage dataService={dataService} />}
        />

        {/* 2 Contextual Investigation Routes */}
        <Route path="alerts/flow/:flowId" element={<FlowInvestigationPage dataService={dataService} />} />
        <Route path="flows/:flowId" element={<FlowInvestigationPage dataService={dataService} />} />

        {/* Catch-all fallback */}
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Route>
    </Routes>
  );
};
