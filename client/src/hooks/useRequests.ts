import { useCallback } from 'react';
import { useAppContext } from '../contexts/AppContext';
import { requestApi, CreateRequestRequest, ApproveRequestRequest, DenyRequestRequest } from '../services/requestApi';
import { ApiError } from '../services/apiClient';

export function useRequests() {
  const { state, dispatch } = useAppContext();

  const loadRequests = useCallback(async () => {
    dispatch({ type: 'REQUESTS_LOAD_START' });
    
    try {
      const response = await requestApi.getRequests();
      
      if (response.success && response.data) {
        dispatch({ type: 'REQUESTS_LOAD_SUCCESS', payload: response.data });
        return { success: true };
      } else {
        throw new Error(response.error?.message || 'Failed to load requests');
      }
    } catch (error) {
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : error instanceof Error 
        ? error.message 
        : 'Failed to load requests';
      
      dispatch({ type: 'REQUESTS_LOAD_FAILURE', payload: errorMessage });
      
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

  const createRequest = useCallback(async (requestData: CreateRequestRequest) => {
    dispatch({ type: 'SET_LOADING', payload: { key: 'general', value: true } });
    
    try {
      const response = await requestApi.createRequest(requestData);
      
      if (response.success && response.data) {
        dispatch({ type: 'REQUEST_CREATE_SUCCESS', payload: response.data });
        
        dispatch({
          type: 'ADD_NOTIFICATION',
          payload: {
            type: 'success',
            message: 'Password request submitted successfully',
          },
        });
        
        return { success: true, data: response.data };
      } else {
        throw new Error(response.error?.message || 'Failed to create request');
      }
    } catch (error) {
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : error instanceof Error 
        ? error.message 
        : 'Failed to create request';
      
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

  const getRequestStatus = useCallback(async (requestId: string) => {
    try {
      const response = await requestApi.getRequestStatus(requestId);
      
      if (response.success && response.data) {
        dispatch({ type: 'SET_CURRENT_REQUEST', payload: response.data });
        return { success: true, data: response.data };
      } else {
        throw new Error(response.error?.message || 'Failed to get request status');
      }
    } catch (error) {
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : error instanceof Error 
        ? error.message 
        : 'Failed to get request status';
      
      return { success: false, error: errorMessage };
    }
  }, [dispatch]);

  const approveRequest = useCallback(async (requestId: string, data: ApproveRequestRequest) => {
    dispatch({ type: 'SET_LOADING', payload: { key: 'general', value: true } });
    
    try {
      const response = await requestApi.approveRequest(requestId, data);
      
      if (response.success && response.data) {
        dispatch({ type: 'REQUEST_UPDATE_SUCCESS', payload: response.data });
        
        dispatch({
          type: 'ADD_NOTIFICATION',
          payload: {
            type: 'success',
            message: 'Request approved successfully',
          },
        });
        
        return { success: true, data: response.data };
      } else {
        throw new Error(response.error?.message || 'Failed to approve request');
      }
    } catch (error) {
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : error instanceof Error 
        ? error.message 
        : 'Failed to approve request';
      
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

  const denyRequest = useCallback(async (requestId: string, data: DenyRequestRequest) => {
    dispatch({ type: 'SET_LOADING', payload: { key: 'general', value: true } });
    
    try {
      const response = await requestApi.denyRequest(requestId, data);
      
      if (response.success && response.data) {
        dispatch({ type: 'REQUEST_UPDATE_SUCCESS', payload: response.data });
        
        dispatch({
          type: 'ADD_NOTIFICATION',
          payload: {
            type: 'success',
            message: 'Request denied successfully',
          },
        });
        
        return { success: true, data: response.data };
      } else {
        throw new Error(response.error?.message || 'Failed to deny request');
      }
    } catch (error) {
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : error instanceof Error 
        ? error.message 
        : 'Failed to deny request';
      
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
    requests: state.requests,
    currentRequest: state.currentRequest,
    loading: state.loading.requests,
    error: state.error.requests,
    loadRequests,
    createRequest,
    getRequestStatus,
    approveRequest,
    denyRequest,
  };
}