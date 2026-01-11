import React, { useEffect } from 'react';
import { ApprovalPanel } from '../components/admin/ApprovalPanel';
import { useRequests } from '../hooks/useRequests';
import { useSocket } from '../hooks/useSocket';

export function AdminApprovalsPage() {
  const { requests, loadRequests, approveRequest, denyRequest, loading, error } = useRequests();
  const { joinAdminRoom } = useSocket();

  useEffect(() => {
    loadRequests();
    joinAdminRoom();
  }, [loadRequests, joinAdminRoom]);

  return (
    <ApprovalPanel
      requests={requests}
      onApprove={approveRequest}
      onDeny={denyRequest}
      isLoading={loading}
      error={error}
    />
  );
}