import React, { useState } from 'react';
import { DashboardLayout } from './layouts/DashboardLayout';
import { DashboardPage } from './pages/DashboardPage';
import { HealthPage } from './pages/HealthPage';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('health');

  return (
    <DashboardLayout activeTab={activeTab} onTabChange={setActiveTab}>
      {activeTab === 'dashboard' && (
        <DashboardPage onNavigateToHealth={() => setActiveTab('health')} />
      )}
      {activeTab === 'health' && <HealthPage />}
      {activeTab === 'agents' && (
        <DashboardPage onNavigateToHealth={() => setActiveTab('health')} />
      )}
      {activeTab === 'incidents' && (
        <DashboardPage onNavigateToHealth={() => setActiveTab('health')} />
      )}
    </DashboardLayout>
  );
};

export default App;
