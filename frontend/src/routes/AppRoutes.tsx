import type { FC } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AppShell } from '../components/layout/AppShell';
import { OverviewPage } from '../pages/OverviewPage';
import { AlertsPage } from '../pages/AlertsPage';
import { FlowsPage } from '../pages/FlowsPage';
import { FlowInvestigationPage } from '../pages/FlowInvestigationPage';
import { ThreatAnalysisPage } from '../pages/ThreatAnalysisPage';
import { DetectionAnalyticsPage } from '../pages/DetectionAnalyticsPage';
import { MlIntelligencePage } from '../pages/MlIntelligencePage';
import { SystemMonitoringPage } from '../pages/SystemMonitoringPage';
import { mockDataService } from '../services/MockDataService';

export const AppRoutes: FC = () => {
  return (
    <Routes>
      <Route path="/" element={<AppShell />}>
        {/* Redirect root path to /overview */}
        <Route index element={<Navigate to="/overview" replace />} />

        {/* 7 Primary Navigation Views */}
        <Route path="overview" element={<OverviewPage dataService={mockDataService} />} />
        <Route path="alerts" element={<AlertsPage dataService={mockDataService} />} />
        <Route path="flows" element={<FlowsPage dataService={mockDataService} />} />
        <Route
          path="threat-analysis"
          element={<ThreatAnalysisPage dataService={mockDataService} />}
        />
        <Route
          path="analytics"
          element={<DetectionAnalyticsPage dataService={mockDataService} />}
        />
        <Route
          path="ml-intelligence"
          element={<MlIntelligencePage dataService={mockDataService} />}
        />
        <Route
          path="system-health"
          element={<SystemMonitoringPage dataService={mockDataService} />}
        />

        {/* 2 Contextual Investigation Routes */}
        <Route path="alerts/flow/:flowId" element={<FlowInvestigationPage dataService={mockDataService} />} />
        <Route path="flows/:flowId" element={<FlowInvestigationPage dataService={mockDataService} />} />

        {/* Catch-all fallback */}
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Route>
    </Routes>
  );
};
