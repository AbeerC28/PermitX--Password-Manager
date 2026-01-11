import apiClient, { ApiResponse } from './apiClient';

export interface PasswordAccessRequest {
  requestId: string;
  accessToken: string;
}

export interface PasswordAccessResponse {
  maskedPassword: string;
  expiresAt: string;
}

export interface PasswordCopyRequest {
  requestId: string;
  accessToken: string;
}

export const passwordApi = {
  // Get masked password for approved request
  getPasswordAccess: async (data: PasswordAccessRequest): Promise<ApiResponse<PasswordAccessResponse>> => {
    const response = await apiClient.post('/password/access', data);
    return response.data;
  },

  // Trigger clipboard copy
  copyPassword: async (data: PasswordCopyRequest): Promise<ApiResponse> => {
    const response = await apiClient.post('/password/copy', data);
    return response.data;
  },
};