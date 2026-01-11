import { useCallback } from 'react';
import { useAppContext } from '../contexts/AppContext';

export function useNotifications() {
  const { state, dispatch } = useAppContext();

  const addNotification = useCallback((
    type: 'success' | 'error' | 'warning' | 'info',
    message: string
  ) => {
    dispatch({
      type: 'ADD_NOTIFICATION',
      payload: { type, message },
    });
  }, [dispatch]);

  const removeNotification = useCallback((id: string) => {
    dispatch({
      type: 'REMOVE_NOTIFICATION',
      payload: id,
    });
  }, [dispatch]);

  const clearAllNotifications = useCallback(() => {
    state.notifications.forEach(notification => {
      removeNotification(notification.id);
    });
  }, [state.notifications, removeNotification]);

  return {
    notifications: state.notifications,
    addNotification,
    removeNotification,
    clearAllNotifications,
  };
}