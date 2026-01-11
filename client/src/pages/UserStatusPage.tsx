import React, { useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { RequestStatusDisplay } from '../components/user/RequestStatusDisplay';
import { useRequests } from '../hooks/useRequests';
import { useSocket } from '../hooks/useSocket';

export function UserStatusPage() {
  const { requestId } = useParams<{ requestId: string }>();
  const { currentRequest, getRequestStatus, loading, error } = useRequests();
  const { joinUserRoom } = useSocket();

  useEffect(() => {
    if (requestId) {
      getRequestStatus(requestId);
    }
  }, [requestId, getRequestStatus]);

  useEffect(() => {
    if (currentRequest?.userEmail) {
      joinUserRoom(currentRequest.userEmail);
    }
  }, [currentRequest?.userEmail, joinUserRoom]);

  if (!requestId) {
    return <div>Invalid request ID</div>;
  }

  return (
    <RequestStatusDisplay
      request={currentRequest}
      isLoading={loading}
      error={error}
    />
  );
}