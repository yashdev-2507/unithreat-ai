import { useState, type FC } from 'react';
import { Outlet } from 'react-router-dom';
import { TopHeader } from './TopHeader';
import { Sidebar } from './Sidebar';

export const AppShell: FC = () => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const toggleSidebar = () => {
    setIsSidebarOpen((prev) => !prev);
  };

  const closeSidebar = () => {
    setIsSidebarOpen(false);
  };

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-[var(--bg-dark-soc)] text-slate-100 font-sans">
      {/* Top Header Bar */}
      <TopHeader
        onToggleSidebar={toggleSidebar}
        isSidebarOpen={isSidebarOpen}
      />

      {/* Main Workspace Body */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar Navigation */}
        <Sidebar isOpen={isSidebarOpen} onClose={closeSidebar} />

        {/* Main Content Viewport */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6 bg-[var(--bg-dark-soc)] focus:outline-none min-w-0">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
