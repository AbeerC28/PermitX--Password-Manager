import { useEffect, useCallback, useState } from 'react';
import { useAppContext } from '../contexts/AppContext';
import { socketService, ServerToClientEvents } from '../services/socketService';
import { ApprovalRequest } from '../services/requestApi';

export function useSocket() {
  const { state, dispatch } = useAppContext();
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting' | 'error'>('disconnected');

  // Initialize socket connection
  const connect = useCallback(async (token?: string) => {
    try {
      setConnectionStatus('connecting');
      await socketService.connect(token);
      setConnectionStatus('connected');
    } catch (error) {
      console.error('Socket connection failed:', error);
      setConnectionStatus('error');
      
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: {
          type: 'error',
          message: 'Failed to establish real-time connection',
        },
      });
    }
  }, [dispatch]);

  // Disconnect socket
  const disconnect = useCallback(() => {
    socketService.disconnect();
    setConnectionStatus('disconnected');
  }, []);

  // Join admin room
  const joinAdminRoom = useCallback(() => {
    socketService.joinAdminRoom();
  }, []);

  // Join user room
  const joinUserRoom = useCallback((email: string) => {
    socketService.joinUserRoom(email);
  }, []);

  // Emit request created
  const emitRequestCreated = useCallback((request: ApprovalRequest) => {
    socketService.emitRequestCreated(request);
  }, []);

  // Set up event listeners
  useEffect(() => {
    // Connection status listener
    const handleConnectionStatus = (status: { connected: boolean; timestamp: Date }) => {
      setConnectionStatus(status.connected ? 'connected' : 'disconnected');
      
      if (status.connected) {
        dispatch({
          type: 'ADD_NOTIFICATION',
          payload: {
            type: 'success',
            message: 'Real-time connection established',
          },
        });
      } else {
        dispatch({
          type: 'ADD_NOTIFICATION',
          payload: {
            type: 'warning',
            message: 'Real-time connection lost',
          },
        });
      }
    };

    // Request notification listener (for admin)
    const handleRequestNotification = (request: ApprovalRequest) => {
      dispatch({ type: 'REQUEST_CREATE_SUCCESS', payload: request });
      
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: {
          type: 'info',
          message: `New password request from ${request.userEmail}`,
        },
      });
    };

    // Status update listener (for users)
    const handleStatusUpdate = (request: ApprovalRequest) => {
      dispatch({ type: 'REQUEST_UPDATE_SUCCESS', payload: request });
      
      let message = '';
      let type: 'success' | 'error' | 'warning' | 'info' = 'info';
      
      switch (request.status) {
        case 'approved':
          message = 'Your password request has been approved';
          type = 'success';
          break;
        case 'denied':
          message = `Your password request has been denied${request.adminResponse?.reason ? ': ' + request.adminResponse.reason : ''}`;
          type = 'error';
          break;
        case 'expired':
          message = 'Your password request has expired';
          type = 'warning';
          break;
        default:
          message = `Request status updated: ${request.status}`;
      }
      
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: { type, message },
      });
    };

    // Approval granted listener
    const handleApprovalGranted = (request: ApprovalRequest) => {
      dispatch({ type: 'REQUEST_UPDATE_SUCCESS', payload: request });
      
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: {
          type: 'success',
          message: 'Password access granted! You can now copy your password.',
        },
      });
    };

    // Request expired listener
    const handleRequestExpired = (request: ApprovalRequest) => {
      dispatch({ type: 'REQUEST_UPDATE_SUCCESS', payload: request });
      
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: {
          type: 'warning',
          message: 'Your password request has expired. Please submit a new request.',
        },
      });
    };

    // Register event listeners
    socketService.on('connection-status', handleConnectionStatus);
    socketService.on('request-notification', handleRequestNotification);
    socketService.on('status-update', handleStatusUpdate);
    socketService.on('approval-granted', handleApprovalGranted);
    socketService.on('request-expired', handleRequestExpired);

    // Cleanup listeners on unmount
    return () => {
      socketService.off('connection-status', handleConnectionStatus);
      socketService.off('request-notification', handleRequestNotification);
      socketService.off('status-update', handleStatusUpdate);
      socketService.off('approval-granted', handleApprovalGranted);
      socketService.off('request-expired', handleRequestExpired);
    };
  }, [dispatch]);

  // Auto-connect when authenticated
  useEffect(() => {
    if (state.isAuthenticated && connectionStatus === 'disconnected') {
      const token = localStorage.getItem('authToken');
      connect(token || undefined);
    } else if (!state.isAuthenticated && connectionStatus !== 'disconnected') {
      disconnect();
    }
  }, [state.isAuthenticated, connectionStatus, connect, disconnect]);

  return {
    connectionStatus,
    isConnected: connectionStatus === 'connected',
    connect,
    disconnect,
    joinAdminRoom,
    joinUserRoom,
    emitRequestCreated,
  };
}