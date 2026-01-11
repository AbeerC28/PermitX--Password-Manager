import apiClient, { ApiResponse } from './apiClient';

export interface ApprovalRequest {
  _id: string;
  userId: string;
  userEmail: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  requestedAt: string;
  respondedAt?: string;
  expiresAt: string;
  adminResponse?: {
    adminId: string;
    reason?: string;
    respondedAt: string;
  };
  accessToken?: string;
  accessExpiresAt?: string;
}

export interface CreateRequestRequest {
  email: string;
}

export interface ApproveRequestRequest {
  reason?: string;
}

export interface DenyRequestRequest {
  reason: string;
}

export const requestApi = {
  // Create password request
  createRequest: async (requestData: CreateRequestRequest): Promise<ApiResponse<ApprovalRequest>> => {
    const response = await apiClient.post('/requests', requestData);
    return response.data;
  },

  // Get all requests (admin only)
  getRequests: async (): Promise<ApiResponse<ApprovalRequest[]>> => {
    const response = await apiClient.get('/requests');
    return response.data;
  },

  // Get request status
  getRequestStatus: async (requestId: string): Promise<ApiResponse<ApprovalRequest>> => {
    const response = await apiClient.get(`/requests/status/${requestId}`);
    return response.data;
  },

  // Approve request
  approveRequest: async (requestId: string, data: ApproveRequestRequest): Promise<ApiResponse<ApprovalRequest>> => {
    const response = await apiClient.put(`/requests/${requestId}/approve`, data);
    return response.data;
  },

  // Deny request
  denyRequest: async (requestId: string, data: DenyRequestRequest): Promise<ApiResponse<ApprovalRequest>> => {
    const response = await apiClient.put(`/requests/${requestId}/deny`, data);
    return response.data;
  },
};