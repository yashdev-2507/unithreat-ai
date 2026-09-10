import { useState, useEffect, type FC } from 'react';
import { Outlet } from 'react-router-dom';
import { TopHeader } from './TopHeader';
import { Sidebar } from './Sidebar';
import type { DataService } from '../../services/DataService';
import { webSocketService } from '../../services/WebSocketService';

export interface AppShellProps {
  dataService?: DataService;
}

export const AppShell: FC<AppShellProps> = ({ dataService }) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  useEffect(() => {
    webSocketService.connect();
    return () => {
      webSocketService.disconnect();
    };
  }, []);

  const toggleSidebar = () => {
    setIsSidebarOpen((prev) => !prev);
  };

  const closeSidebar = () => {
    setIsSidebarOpen(false);
  };

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-[#F8FAFC] text-[#0A0A0A] font-sans">
      {/* Top Header Bar */}
      <TopHeader
        onToggleSidebar={toggleSidebar}
        isSidebarOpen={isSidebarOpen}
        dataService={dataService}
      />

      {/* Main Workspace Body */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar Navigation */}
        <Sidebar isOpen={isSidebarOpen} onClose={closeSidebar} />

        {/* Main Content Viewport */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6 bg-[#F8FAFC] bg-dotted-grid focus:outline-none min-w-0">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

