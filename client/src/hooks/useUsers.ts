import { useCallback } from 'react';
import { useAppContext } from '../contexts/AppContext';
import { userApi, CreateUserRequest, UpdateUserRequest } from '../services/userApi';
import { ApiError } from '../services/apiClient';

export function useUsers() {
  const { state, dispatch } = useAppContext();

  const loadUsers = useCallback(async () => {
    dispatch({ type: 'USERS_LOAD_START' });
    
    try {
      const response = await userApi.getUsers();
      
      if (response.success && response.data) {
        dispatch({ type: 'USERS_LOAD_SUCCESS', payload: response.data });
        return { success: true };
      } else {
        throw new Error(response.error?.message || 'Failed to load users');
      }
    } catch (error) {
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : error instanceof Error 
        ? error.message 
        : 'Failed to load users';
      
      dispatch({ type: 'USERS_LOAD_FAILURE', payload: errorMessage });
      
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

  const createUser = useCallback(async (userData: CreateUserRequest) => {
    dispatch({ type: 'SET_LOADING', payload: { key: 'general', value: true } });
    
    try {
      const response = await userApi.createUser(userData);
      
      if (response.success && response.data) {
        dispatch({ type: 'USER_CREATE_SUCCESS', payload: response.data });
        
        dispatch({
          type: 'ADD_NOTIFICATION',
          payload: {
            type: 'success',
            message: `User ${userData.email} created successfully`,
          },
        });
        
        return { success: true, data: response.data };
      } else {
        throw new Error(response.error?.message || 'Failed to create user');
      }
    } catch (error) {
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : error instanceof Error 
        ? error.message 
        : 'Failed to create user';
      
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: {
          type: 'error',
          message: errorMessage,
        },
      });
      
      return { success: false, error: errorMessage };
    } finally {
      dispatch({ type: 'SET_LOADING', payload: { key: 'general', value: false } });
    }
  }, [dispatch]);

  const updateUser = useCallback(async (userId: string, userData: UpdateUserRequest) => {
    dispatch({ type: 'SET_LOADING', payload: { key: 'general', value: true } });
    
    try {
      const response = await userApi.updateUser(userId, userData);
      
      if (response.success && response.data) {
        dispatch({ type: 'USER_UPDATE_SUCCESS', payload: response.data });
        
        dispatch({
          type: 'ADD_NOTIFICATION',
          payload: {
            type: 'success',
            message: 'User updated successfully',
          },
        });
        
        return { success: true, data: response.data };
      } else {
        throw new Error(response.error?.message || 'Failed to update user');
      }
    } catch (error) {
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : error instanceof Error 
        ? error.message 
        : 'Failed to update user';
      
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: {
          type: 'error',
          message: errorMessage,
        },
      });
      
      return { success: false, error: errorMessage };
    } finally {
      dispatch({ type: 'SET_LOADING', payload: { key: 'general', value: false } });
    }
  }, [dispatch]);

  const deleteUser = useCallback(async (userId: string) => {
    dispatch({ type: 'SET_LOADING', payload: { key: 'general', value: true } });
    
    try {
      const response = await userApi.deleteUser(userId);
      
      if (response.success) {
        dispatch({ type: 'USER_DELETE_SUCCESS', payload: userId });
        
        dispatch({
          type: 'ADD_NOTIFICATION',
          payload: {
            type: 'success',
            message: 'User deleted successfully',
          },
        });
        
        return { success: true };
      } else {
        throw new Error(response.error?.message || 'Failed to delete user');
      }
    } catch (error) {
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : error instanceof Error 
        ? error.message 
        : 'Failed to delete user';
      
      dispatch({
        type: 'ADD_NOTIFICATION',
        payload: {
          type: 'error',
          message: errorMessage,
        },
      });
      
      return { success: false, error: errorMessage };
    } finally {
      dispatch({ type: 'SET_LOADING', payload: { key: 'general', value: false } });
    }
  }, [dispatch]);

  return {
    users: state.users,
    loading: state.loading.users,
    error: state.error.users,
    loadUsers,
    createUser,
    updateUser,
    deleteUser,
  };
}