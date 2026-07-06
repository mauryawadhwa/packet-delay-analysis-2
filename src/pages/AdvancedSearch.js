import React, { useState } from 'react';
import { useAnalysis } from '../context/AnalysisContext';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  TextField,
  Button,
  Chip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
} from '@mui/material';
import {
  Search as SearchIcon,
  FilterList as FilterIcon,
} from '@mui/icons-material';

const AdvancedSearch = () => {
  const { analysisData } = useAnalysis();
  const [filters, setFilters] = useState({
    protocol: '',
    sourceIp: '',
    destinationIp: '',
    minDelay: '',
    maxDelay: '',
    port: '',
  });
  const [activeFilters, setActiveFilters] = useState([]);
  const [searchResults, setSearchResults] = useState([]);

  const handleFilterChange = (field, value) => {
    setFilters(prev => ({
      ...prev,
      [field]: value,
    }));
  };

  const addFilter = (field) => {
    if (filters[field] && !activeFilters.find(f => f.field === field)) {
      setActiveFilters(prev => [...prev, {
        field,
        value: filters[field],
        id: Date.now(),
      }]);
    }
  };

  const removeFilter = (filterId) => {
    setActiveFilters(prev => prev.filter(f => f.id !== filterId));
  };

  const clearAllFilters = () => {
    setFilters({
      protocol: '',
      sourceIp: '',
      destinationIp: '',
      minDelay: '',
      maxDelay: '',
      port: '',
    });
    setActiveFilters([]);
  };

  const handleSearch = () => {
    if (!analysisData || !analysisData.packets) {
      setSearchResults([]);
      return;
    }

    let results = analysisData.packets;

    activeFilters.forEach(filter => {
      const value = filter.value.toString().toLowerCase();
      switch (filter.field) {
        case 'protocol':
          results = results.filter(p => p.protocol.toLowerCase() === value);
          break;
        case 'sourceIp':
          results = results.filter(p => p.src_ip.toLowerCase().includes(value));
          break;
        case 'destinationIp':
          results = results.filter(p => p.dst_ip.toLowerCase().includes(value));
          break;
        case 'minDelay':
          results = results.filter(p => p.delay !== null && p.delay >= parseFloat(value));
          break;
        case 'maxDelay':
          results = results.filter(p => p.delay !== null && p.delay <= parseFloat(value));
          break;
        case 'port':
          results = results.filter(p => p.flow_key.includes(`:${value}-`) || p.flow_key.endsWith(`:${value}-TCP`) || p.flow_key.endsWith(`:${value}-UDP`));
          break;
        default:
          break;
      }
    });

    setSearchResults(results.map((p, i) => {
      const ports = p.flow_key.split('-').slice(0, 2).map(part => part.split(':')[1]).join(' / ');
      return {
        id: i,
        timestamp: p.timestamp * 1000,
        protocol: p.protocol,
        sourceIp: p.src_ip,
        destinationIp: p.dst_ip,
        delay: p.delay !== null ? p.delay.toFixed(4) : '-',
        port: ports
      };
    }));
  };

  const renderFilterField = (field, label, type = 'text') => (
    <Grid item xs={12} sm={6} md={4}>
      <TextField
        fullWidth
        label={label}
        type={type}
        value={filters[field]}
        onChange={(e) => handleFilterChange(field, e.target.value)}
        InputProps={{
          endAdornment: (
            <IconButton
              size="small"
              onClick={() => addFilter(field)}
              disabled={!filters[field]}
            >
              <FilterIcon />
            </IconButton>
          ),
        }}
      />
    </Grid>
  );

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Advanced Search & Filtering
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Search Filters
              </Typography>
              
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6} md={4}>
                  <FormControl fullWidth>
                    <InputLabel>Protocol</InputLabel>
                    <Select
                      value={filters.protocol}
                      onChange={(e) => handleFilterChange('protocol', e.target.value)}
                    >
                      <MenuItem value="">All</MenuItem>
                      <MenuItem value="TCP">TCP</MenuItem>
                      <MenuItem value="UDP">UDP</MenuItem>
                      <MenuItem value="ICMP">ICMP</MenuItem>
                      <MenuItem value="HTTP">HTTP</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>

                {renderFilterField('sourceIp', 'Source IP')}
                {renderFilterField('destinationIp', 'Destination IP')}
                {renderFilterField('minDelay', 'Min Delay (ms)', 'number')}
                {renderFilterField('maxDelay', 'Max Delay (ms)', 'number')}
                {renderFilterField('port', 'Port', 'number')}

                <Grid item xs={12}>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    {activeFilters.map(filter => (
                      <Chip
                        key={filter.id}
                        label={`${filter.field}: ${filter.value}`}
                        onDelete={() => removeFilter(filter.id)}
                        color="primary"
                        variant="outlined"
                      />
                    ))}
                    {activeFilters.length > 0 && (
                      <Chip
                        label="Clear All"
                        onDelete={clearAllFilters}
                        color="error"
                      />
                    )}
                  </Box>
                </Grid>

                <Grid item xs={12}>
                  <Button
                    variant="contained"
                    startIcon={<SearchIcon />}
                    onClick={handleSearch}
                    disabled={activeFilters.length === 0}
                  >
                    Search
                  </Button>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        {searchResults.length > 0 && (
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Search Results
                </Typography>
                
                <TableContainer component={Paper}>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Timestamp</TableCell>
                        <TableCell>Protocol</TableCell>
                        <TableCell>Source IP</TableCell>
                        <TableCell>Destination IP</TableCell>
                        <TableCell>Delay (ms)</TableCell>
                        <TableCell>Port</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {searchResults.map((result) => (
                        <TableRow key={result.id}>
                          <TableCell>{new Date(result.timestamp).toLocaleString()}</TableCell>
                          <TableCell>{result.protocol}</TableCell>
                          <TableCell>{result.sourceIp}</TableCell>
                          <TableCell>{result.destinationIp}</TableCell>
                          <TableCell>{result.delay}</TableCell>
                          <TableCell>{result.port}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </CardContent>
            </Card>
          </Grid>
        )}
      </Grid>
    </Box>
  );
};

export default AdvancedSearch;
