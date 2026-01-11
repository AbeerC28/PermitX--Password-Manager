import React, { useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { PasswordAccessPanel } from '../components/user/PasswordAccessPanel';
import { useRequests } from '../hooks/useRequests';

export function UserAccessPage() {
  const { requestId } = useParams<{ requestId: string }>();
  const { currentRequest, getRequestStatus, loading, error } = useRequests();

  useEffect(() => {
    if (requestId) {
      getRequestStatus(requestId);
    }
  }, [requestId, getRequestStatus]);

  if (!requestId) {
    return <div>Invalid request ID</div>;
  }

  return (
    <PasswordAccessPanel
      requestId={requestId}
      request={currentRequest}
      isLoading={loading}
      error={error}
    />
  );
}