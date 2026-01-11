import apiClient, { ApiResponse } from './apiClient';

export interface User {
  _id: string;
  email: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  lastPasswordUpdate: string;
}

export interface CreateUserRequest {
  email: string;
  password: string;
}

export interface UpdateUserRequest {
  password: string;
}

export const userApi = {
  // Create new user
  createUser: async (userData: CreateUserRequest): Promise<ApiResponse<User>> => {
    const response = await apiClient.post('/users', userData);
    return response.data;
  },

  // Get all users
  getUsers: async (): Promise<ApiResponse<User[]>> => {
    const response = await apiClient.get('/users');
    return response.data;
  },

  // Update user password
  updateUser: async (userId: string, userData: UpdateUserRequest): Promise<ApiResponse<User>> => {
    const response = await apiClient.put(`/users/${userId}`, userData);
    return response.data;
  },

  // Delete user
  deleteUser: async (userId: string): Promise<ApiResponse> => {
    const response = await apiClient.delete(`/users/${userId}`);
    return response.data;
  },
};