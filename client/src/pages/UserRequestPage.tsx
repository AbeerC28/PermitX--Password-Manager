import React from 'react';
import { useNavigate } from 'react-router-dom';
import { LoginRequestForm } from '../components/user/LoginRequestForm';
import { useRequests } from '../hooks/useRequests';
import { useSocket } from '../hooks/useSocket';

export function UserRequestPage() {
  const navigate = useNavigate();
  const { createRequest, loading, error } = useRequests();
  const { emitRequestCreated } = useSocket();

  const handleSubmit = async (email: string) => {
    const result = await createRequest({ email });
    
    if (result.success && result.data) {
      // Emit socket event for real-time updates
      emitRequestCreated(result.data);
      
      // Navigate to status page
      navigate(`/status/${result.data._id}`);
    }
  };

  return (
    <LoginRequestForm
      onSubmit={handleSubmit}
      isLoading={loading}
      error={error}
    />
  );
}