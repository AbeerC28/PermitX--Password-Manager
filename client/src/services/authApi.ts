import apiClient, { ApiResponse } from './apiClient';

export interface AdminLoginRequest {
  username: string;
  password: string;
}

export interface AdminLoginResponse {
  token: string;
  admin: {
    id: string;
    username: string;
    email: string;
  };
}

export interface AdminVerifyResponse {
  admin: {
    id: string;
    username: string;
    email: string;
  };
}

export const authApi = {
  // Admin login
  adminLogin: async (credentials: AdminLoginRequest): Promise<ApiResponse<AdminLoginResponse>> => {
    const response = await apiClient.post('/auth/admin/login', credentials);
    return response.data;
  },

  // Admin logout
  adminLogout: async (): Promise<ApiResponse> => {
    const response = await apiClient.post('/auth/admin/logout');
    return response.data;
  },

  // Verify admin session
  verifyAdmin: async (): Promise<ApiResponse<AdminVerifyResponse>> => {
    const response = await apiClient.get('/auth/admin/verify');
    return response.data;
  },
};