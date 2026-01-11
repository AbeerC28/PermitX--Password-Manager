import React, { useEffect, useCallback } from 'react';
import { useAuth } from '../../hooks/useAuth';
import { useSocket } from '../../hooks/useSocket';

interface SessionManagerProps {
  children: React.ReactNode;
}

export function SessionManager({ children }: SessionManagerProps) {
  const { isAuthenticated, verifySession, logout } = useAuth();
  const { disconnect } = useSocket();

  // Session verification interval (every 5 minutes)
  const SESSION_CHECK_INTERVAL = 5 * 60 * 1000;

  const handleSessionCheck = useCallback(async () => {
    if (isAuthenticated) {
      const result = await verifySession();
      if (!result.success) {
        // Session is invalid, logout user
        await logout();
        disconnect();
      }
    }
  }, [isAuthenticated, verifySession, logout, disconnect]);

  // Set up periodic session verification
  useEffect(() => {
    if (!isAuthenticated) {
      return;
    }

    const interval = setInterval(handleSessionCheck, SESSION_CHECK_INTERVAL);

    return () => {
      clearInterval(interval);
    };
  }, [isAuthenticated, handleSessionCheck]);

  // Handle browser visibility change - verify session when tab becomes visible
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && isAuthenticated) {
        handleSessionCheck();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [isAuthenticated, handleSessionCheck]);

  // Handle browser beforeunload - cleanup on page unload
  useEffect(() => {
    const handleBeforeUnload = () => {
      if (isAuthenticated) {
        disconnect();
      }
    };

    window.addEventListener('beforeunload', handleBeforeUnload);

    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [isAuthenticated, disconnect]);

  // Handle storage events - logout if token is removed in another tab
  useEffect(() => {
    const handleStorageChange = (event: StorageEvent) => {
      if (event.key === 'authToken' && event.newValue === null && isAuthenticated) {
        // Token was removed in another tab, logout this tab too
        logout();
        disconnect();
      }
    };

    window.addEventListener('storage', handleStorageChange);

    return () => {
      window.removeEventListener('storage', handleStorageChange);
    };
  }, [isAuthenticated, logout, disconnect]);

  return <>{children}</>;
}