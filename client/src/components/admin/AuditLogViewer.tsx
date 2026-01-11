import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Button,
  Chip,
  CircularProgress,
  Alert,
  Card,
  CardContent,
  Grid,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Pagination,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  History as HistoryIcon,
  Info as InfoIcon,
  Warning as WarningIcon,
  Error as ErrorIcon
} from '@mui/icons-material';

export interface AuditLog {
  _id: string;
  action: string;
  userId?: string;
  adminId?: string;
  userEmail?: string;
  adminEmail?: string;
  details: Record<string, any>;
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
  severity: 'info' | 'warning' | 'error';
}

export interface AuditLogFilters {
  search?: string;
  action?: string;
  severity?: string;
  dateFrom?: string;
  dateTo?: string;
  userId?: string;
}

interface AuditLogViewerProps {
  logs: AuditLog[];
  totalCount: number;
  currentPage: number;
  pageSize: number;
  isLoading?: boolean;
  error?: string;
  onSearch: (filters: AuditLogFilters, page: number) => Promise<void>;
  onRefresh?: () => void;
}

export const AuditLogViewer: React.FC<AuditLogViewerProps> = ({
  logs,
  totalCount,
  currentPage,
  pageSize,
  isLoading = false,
  error,
  onSearch,
  onRefresh
}) => {
  const [filters, setFilters] = useState<AuditLogFilters>({});
  const [expandedLog, setExpandedLog] = useState<string | null>(null);

  const totalPages = Math.ceil(totalCount / pageSize);

  const handleSearch = () => {
    onSearch(filters, 1);
  };

  const handlePageChange = (_event: React.ChangeEvent<unknown>, page: number) => {
    onSearch(filters, page);
  };

  const handleFilterChange = (key: keyof AuditLogFilters, value: string) => {
    setFilters(prev => ({
      ...prev,
      [key]: value || undefined
    }));
  };

  const clearFilters = () => {
    setFilters({});
    onSearch({}, 1);
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'error':
        return <ErrorIcon color="error" fontSize="small" />;
      case 'warning':
        return <WarningIcon color="warning" fontSize="small" />;
      case 'info':
      default:
        return <InfoIcon color="info" fontSize="small" />;
    }
  };

  const getSeverityColor = (severity: string): 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' => {
    switch (severity) {
      case 'error':
        return 'error';
      case 'warning':
        return 'warning';
      case 'info':
      default:
        return 'info';
    }
  };

  const formatDate = (date: Date | string) => {
    return new Date(date).toLocaleString();
  };

  const formatDetails = (details: Record<string, any>) => {
    return Object.entries(details)
      .filter(([_key, value]) => value !== null && value !== undefined)
      .map(([key, value]) => (
        <Box key={key} sx={{ mb: 1 }}>
          <Typography variant="caption" color="text.secondary">
            {key}:
          </Typography>
          <Typography variant="body2" component="div">
            {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
          </Typography>
        </Box>
      ));
  };

  const actionTypes = [
    'user_created', 'user_updated', 'user_deleted',
    'request_created', 'request_approved', 'request_denied',
    'password_accessed', 'admin_login', 'admin_logout'
  ];

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box display="flex" alignItems="center" gap={2}>
          <HistoryIcon color="primary" fontSize="large" />
          <Typography variant="h4" component="h1">
            Audit Log Viewer
          </Typography>
        </Box>
        
        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          onClick={onRefresh}
          disabled={isLoading}
        >
          Refresh
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Search and Filters */}
      <Paper elevation={3} sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Search & Filters
        </Typography>
        
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth
              label="Search"
              placeholder="Search logs..."
              value={filters.search || ''}
              onChange={(e) => handleFilterChange('search', e.target.value)}
              size="small"
            />
          </Grid>
          
          <Grid item xs={12} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Action</InputLabel>
              <Select
                value={filters.action || ''}
                onChange={(e) => handleFilterChange('action', e.target.value)}
                label="Action"
              >
                <MenuItem value="">All Actions</MenuItem>
                {actionTypes.map(action => (
                  <MenuItem key={action} value={action}>
                    {action.replace('_', ' ').toUpperCase()}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Severity</InputLabel>
              <Select
                value={filters.severity || ''}
                onChange={(e) => handleFilterChange('severity', e.target.value)}
                label="Severity"
              >
                <MenuItem value="">All Severities</MenuItem>
                <MenuItem value="info">Info</MenuItem>
                <MenuItem value="warning">Warning</MenuItem>
                <MenuItem value="error">Error</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} md={2}>
            <TextField
              fullWidth
              label="From Date"
              type="date"
              value={filters.dateFrom || ''}
              onChange={(e) => handleFilterChange('dateFrom', e.target.value)}
              size="small"
              InputLabelProps={{ shrink: true }}
            />
          </Grid>
          
          <Grid item xs={12} md={2}>
            <TextField
              fullWidth
              label="To Date"
              type="date"
              value={filters.dateTo || ''}
              onChange={(e) => handleFilterChange('dateTo', e.target.value)}
              size="small"
              InputLabelProps={{ shrink: true }}
            />
          </Grid>
        </Grid>
        
        <Box display="flex" gap={2} mt={2}>
          <Button
            variant="contained"
            startIcon={<SearchIcon />}
            onClick={handleSearch}
            disabled={isLoading}
          >
            Search
          </Button>
          <Button
            variant="outlined"
            onClick={clearFilters}
            disabled={isLoading}
          >
            Clear Filters
          </Button>
        </Box>
      </Paper>

      {/* Results Summary */}
      <Card variant="outlined" sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="body1">
            Showing {logs.length} of {totalCount} audit log entries
            {currentPage > 1 && ` (Page ${currentPage} of ${totalPages})`}
          </Typography>
        </CardContent>
      </Card>

      {/* Audit Logs Table */}
      <Paper elevation={3}>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Timestamp</TableCell>
                <TableCell>Action</TableCell>
                <TableCell>User/Admin</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>IP Address</TableCell>
                <TableCell>Details</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                    <CircularProgress />
                  </TableCell>
                </TableRow>
              ) : logs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                    <Typography color="text.secondary">
                      No audit logs found matching your criteria.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                logs.map((log) => (
                  <React.Fragment key={log._id}>
                    <TableRow hover>
                      <TableCell>
                        <Typography variant="body2">
                          {formatDate(log.timestamp)}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {log.action.replace('_', ' ').toUpperCase()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {log.userEmail || log.adminEmail || 'System'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Box display="flex" alignItems="center" gap={1}>
                          {getSeverityIcon(log.severity)}
                          <Chip
                            label={log.severity.toUpperCase()}
                            color={getSeverityColor(log.severity)}
                            size="small"
                          />
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace">
                          {log.ipAddress}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Button
                          size="small"
                          onClick={() => setExpandedLog(
                            expandedLog === log._id ? null : log._id
                          )}
                        >
                          {expandedLog === log._id ? 'Hide' : 'Show'} Details
                        </Button>
                      </TableCell>
                    </TableRow>
                    {expandedLog === log._id && (
                      <TableRow>
                        <TableCell colSpan={6}>
                          <Accordion expanded>
                            <AccordionSummary>
                              <Typography variant="subtitle2">
                                Detailed Information
                              </Typography>
                            </AccordionSummary>
                            <AccordionDetails>
                              <Grid container spacing={2}>
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" gutterBottom>
                                    User Agent
                                  </Typography>
                                  <Typography variant="body2" fontFamily="monospace" sx={{ mb: 2 }}>
                                    {log.userAgent}
                                  </Typography>
                                </Grid>
                                <Grid item xs={12} md={6}>
                                  <Typography variant="subtitle2" gutterBottom>
                                    Additional Details
                                  </Typography>
                                  <Box>
                                    {formatDetails(log.details)}
                                  </Box>
                                </Grid>
                              </Grid>
                            </AccordionDetails>
                          </Accordion>
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Pagination */}
        {totalPages > 1 && (
          <Box display="flex" justifyContent="center" sx={{ p: 2 }}>
            <Pagination
              count={totalPages}
              page={currentPage}
              onChange={handlePageChange}
              color="primary"
              disabled={isLoading}
            />
          </Box>
        )}
      </Paper>
    </Box>
  );
};