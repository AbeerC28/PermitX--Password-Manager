import React from 'react';
import { NotificationToast } from './NotificationToast';
import { useNotifications } from '../../hooks/useNotifications';

export function NotificationSystem() {
  const { notifications, removeNotification } = useNotifications();

  return (
    <NotificationToast
      notifications={notifications}
      onClose={removeNotification}
    />
  );
}