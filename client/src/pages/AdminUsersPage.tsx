import React, { useEffect } from 'react';
import { UserManagement } from '../components/admin/UserManagement';
import { useUsers } from '../hooks/useUsers';

export function AdminUsersPage() {
  const { users, loadUsers, createUser, updateUser, deleteUser, loading, error } = useUsers();

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  return (
    <UserManagement
      users={users}
      onCreateUser={createUser}
      onUpdateUser={updateUser}
      onDeleteUser={deleteUser}
      isLoading={loading}
      error={error}
    />
  );
}