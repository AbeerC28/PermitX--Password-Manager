import React, { useState, useEffect } from 'react';
import {
  Snackbar,
  Alert,
  AlertTitle,
  Slide,
  SlideProps
} from '@mui/material';

export interface NotificationData {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title?: string;
  message: string;
  duration?: number;
  persistent?: boolean;
}

interface NotificationToastProps {
  notifications: NotificationData[];
  onClose: (id: string) => void;
  maxVisible?: number;
}

function SlideTransition(props: SlideProps) {
  return <Slide {...props} direction="up" />;
}

export const NotificationToast: React.FC<NotificationToastProps> = ({
  notifications,
  onClose,
  maxVisible = 3
}) => {
  const [visibleNotifications, setVisibleNotifications] = useState<NotificationData[]>([]);

  useEffect(() => {
    // Show only the most recent notifications up to maxVisible
    const recent = notifications.slice(-maxVisible);
    setVisibleNotifications(recent);
  }, [notifications, maxVisible]);

  const handleClose = (id: string, reason?: string) => {
    // Don't close on clickaway for persistent notifications
    if (reason === 'clickaway') {
      const notification = visibleNotifications.find(n => n.id === id);
      if (notification?.persistent) {
        return;
      }
    }
    onClose(id);
  };

  return (
    <>
      {visibleNotifications.map((notification, index) => (
        <Snackbar
          key={notification.id}
          open={true}
          autoHideDuration={notification.persistent ? null : (notification.duration || 6000)}
          onClose={(_, reason) => handleClose(notification.id, reason)}
          TransitionComponent={SlideTransition}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
          sx={{
            // Stack notifications vertically
            bottom: `${(index * 80) + 24}px !important`,
            right: '24px !important',
            position: 'fixed'
          }}
        >
          <Alert
            onClose={() => handleClose(notification.id)}
            severity={notification.type}
            variant="filled"
            sx={{
              minWidth: '300px',
              maxWidth: '500px',
              boxShadow: 3
            }}
          >
            {notification.title && (
              <AlertTitle>{notification.title}</AlertTitle>
            )}
            {notification.message}
          </Alert>
        </Snackbar>
      ))}
    </>
  );
};

// Hook for managing notifications
export const useNotifications = () => {
  const [notifications, setNotifications] = useState<NotificationData[]>([]);

  const addNotification = (notification: Omit<NotificationData, 'id'>) => {
    const id = `notification-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const newNotification: NotificationData = {
      id,
      ...notification
    };

    setNotifications(prev => [...prev, newNotification]);

    // Auto-remove non-persistent notifications
    if (!notification.persistent) {
      setTimeout(() => {
        removeNotification(id);
      }, notification.duration || 6000);
    }

    return id;
  };

  const removeNotification = (id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };

  const clearAllNotifications = () => {
    setNotifications([]);
  };

  // Convenience methods for different notification types
  const showSuccess = (message: string, title?: string, options?: Partial<NotificationData>) => {
    return addNotification({ type: 'success', message, title, ...options });
  };

  const showError = (message: string, title?: string, options?: Partial<NotificationData>) => {
    return addNotification({ type: 'error', message, title, ...options });
  };

  const showWarning = (message: string, title?: string, options?: Partial<NotificationData>) => {
    return addNotification({ type: 'warning', message, title, ...options });
  };

  const showInfo = (message: string, title?: string, options?: Partial<NotificationData>) => {
    return addNotification({ type: 'info', message, title, ...options });
  };

  return {
    notifications,
    addNotification,
    removeNotification,
    clearAllNotifications,
    showSuccess,
    showError,
    showWarning,
    showInfo
  };
};