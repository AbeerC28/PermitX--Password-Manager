import React, { useState } from 'react';
import {
  Box,
  TextField,
  Button,
  Paper,
  Typography,
  Alert,
  CircularProgress
} from '@mui/material';
import { Send as SendIcon } from '@mui/icons-material';

interface LoginRequestFormProps {
  onSubmit: (email: string) => Promise<void>;
  isLoading?: boolean;
  error?: string;
}

export const LoginRequestForm: React.FC<LoginRequestFormProps> = ({
  onSubmit,
  isLoading = false,
  error
}) => {
  const [email, setEmail] = useState('');
  const [emailError, setEmailError] = useState('');

  const validateEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email) {
      setEmailError('Email is required');
      return false;
    }
    if (!emailRegex.test(email)) {
      setEmailError('Please enter a valid email address');
      return false;
    }
    setEmailError('');
    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateEmail(email)) {
      return;
    }

    try {
      await onSubmit(email);
      setEmail(''); // Clear form on successful submission
    } catch (err) {
      // Error handling is managed by parent component
    }
  };

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setEmail(value);
    if (emailError && value) {
      validateEmail(value);
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 4, maxWidth: 400, mx: 'auto' }}>
      <Typography variant="h5" component="h2" gutterBottom align="center">
        Request Password Access
      </Typography>
      
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }} align="center">
        Enter your email to request access to your password. An admin will review your request.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Box component="form" onSubmit={handleSubmit}>
        <TextField
          fullWidth
          label="Email Address"
          type="email"
          value={email}
          onChange={handleEmailChange}
          error={!!emailError}
          helperText={emailError}
          disabled={isLoading}
          sx={{ mb: 3 }}
          autoFocus
        />

        <Button
          type="submit"
          fullWidth
          variant="contained"
          size="large"
          disabled={isLoading || !!emailError}
          startIcon={isLoading ? <CircularProgress size={20} /> : <SendIcon />}
        >
          {isLoading ? 'Submitting Request...' : 'Submit Request'}
        </Button>
      </Box>
    </Paper>
  );
};