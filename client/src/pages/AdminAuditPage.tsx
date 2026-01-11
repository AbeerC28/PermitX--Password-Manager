import React, { useState, useEffect } from 'react';
import { AuditLogViewer } from '../components/admin/AuditLogViewer';

// Mock audit logs for now - this would be replaced with actual API calls
const mockAuditLogs = [
  {
    _id: '1',
    action: 'User Login',
    userId: 'user1',
    adminId: 'admin1',
    details: { ip: '192.168.1.1' },
    ipAddress: '192.168.1.1',
    userAgent: 'Mozilla/5.0...',
    timestamp: new Date().toISOString(),
    severity: 'info' as const,
  },
];

export function AdminAuditPage() {
  const [logs] = useState(mockAuditLogs);
  const [totalCount] = useState(mockAuditLogs.length);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(10);

  const handleSearch = (query: string) => {
    console.log('Searching audit logs:', query);
    // This would trigger an API call to search logs
  };

  const handlePageChange = (page: number) => {
    setCurrentPage(page);
    // This would trigger an API call to load the specific page
  };

  return (
    <AuditLogViewer
      logs={logs}
      totalCount={totalCount}
      currentPage={currentPage}
      pageSize={pageSize}
      onSearch={handleSearch}
      onPageChange={handlePageChange}
    />
  );
}