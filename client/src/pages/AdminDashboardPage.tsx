import React, { useEffect } from 'react';
import { AdminDashboard } from '../components/admin/AdminDashboard';
import { useRequests } from '../hooks/useRequests';
import { useUsers } from '../hooks/useUsers';
import { useSocket } from '../hooks/useSocket';

export function AdminDashboardPage() {
  const { requests, loadRequests } = useRequests();
  const { users, loadUsers } = useUsers();
  const { joinAdminRoom } = useSocket();

  useEffect(() => {
    loadRequests();
    loadUsers();
    joinAdminRoom();
  }, [loadRequests, loadUsers, joinAdminRoom]);

  // Calculate stats
  const stats = {
    totalUsers: users.length,
    pendingRequests: requests.filter(r => r.status === 'pending').length,
    approvedToday: requests.filter(r => 
      r.status === 'approved' && 
      new Date(r.respondedAt || '').toDateString() === new Date().toDateString()
    ).length,
    activeUsers: users.filter(u => u.isActive).length,
  };

  // Get recent requests (last 10)
  const recentRequests = requests
    .sort((a, b) => new Date(b.requestedAt).getTime() - new Date(a.requestedAt).getTime())
    .slice(0, 10);

  return (
    <AdminDashboard
      stats={stats}
      recentRequests={recentRequests}
    />
  );
}