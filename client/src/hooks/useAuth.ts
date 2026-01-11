import { useCallback } from 'react';
import { useAppContext } from '../contexts/AppContext';
import { authApi, AdminLoginRequest } from '../services/authApi';
import { ApiError } from '../services/apiClient';

export function useAuth() {
  const { state, dispatch } = useAppContext();

  const login = useCallback(async (credentials: AdminLoginRequest) => {
    dispatch({ type: 'AUTH_START' });
    
    try {
      const response = await authApi.adminLogin(credentials);
      
      if (response.success && response.data) {
        dispatch({
          type: 'AUTH_SUCCESS',
          payload: {
            admin: response.data.admin,
            token: response.data.token,
          },
        });
        
        dispatch({
          type: 'ADD_NOTIFICATION',
          payload: {
            type: 'success',
            message: 'Successfully logged in',
          },
        });
        
        return { success: true };
      } else {
        throw new Error(response.error?.message || 'Login failed');
      }
    } catch (error) {
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : error instanceof Error 
        ? error.message 
        : 'Login failed';
      
      dispatch({ type: 'AUTH_FAILURE', payload: errorMessage });
      
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: {
          type: 'error',
          message: errorMessage,
        },
      });
      
      return { success: false, error: errorMessage };
    }
  }, [dispatch]);

  const logout = useCallback(async () => {
    try {
      await authApi.adminLogout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      dispatch({ type: 'AUTH_LOGOUT' });
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: {
          type: 'info',
          message: 'Successfully logged out',
        },
      });
    }
  }, [dispatch]);

  const verifySession = useCallback(async () => {
    const token = localStorage.getItem('authToken');
    if (!token) {
      return { success: false };
    }

    dispatch({ type: 'AUTH_START' });
    
    try {
      const response = await authApi.verifyAdmin();
      
      if (response.success && response.data) {
        dispatch({
          type: 'AUTH_SUCCESS',
          payload: {
            admin: response.data.admin,
            token,
          },
        });
        
        return { success: true };
      } else {
        throw new Error('Session verification failed');
      }
    } catch (error) {
      dispatch({ type: 'AUTH_FAILURE', payload: 'Session expired' });
      return { success: false };
    }
  }, [dispatch]);

  return {
    isAuthenticated: state.isAuthenticated,
    admin: state.admin,
    loading: state.loading.auth,
    error: state.error.auth,
    login,
    logout,
    verifySession,
  };
}