import React from 'react';
import { useAnalysis } from '../context/AnalysisContext';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  LinearProgress,
  Chip,
  useTheme,
} from '@mui/material';
import {
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckIcon,
  Info as InfoIcon,
} from '@mui/icons-material';

const DelayCategories = () => {
  const theme = useTheme();
  const { analysisData } = useAnalysis();

  if (!analysisData || Object.keys(analysisData).length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography variant="h5">No data available. Please upload a file first.</Typography>
      </Box>
    );
  }

  const delayCategories = [
    {
      type: 'Network Congestion',
      description: 'Delays caused by network congestion and bandwidth limitations',
      severity: analysisData.congestionLevel || 'low',
      percentage: analysisData.congestionPercentage || 15,
      icon: <WarningIcon />,
      color: theme.palette.warning.main,
    },
    {
      type: 'Queuing Delay',
      description: 'Delays from packet queuing at network devices',
      severity: analysisData.queuingLevel || 'medium',
      percentage: analysisData.queuingPercentage || 25,
      icon: <InfoIcon />,
      color: theme.palette.info.main,
    },
    {
      type: 'Routing Inefficiency',
      description: 'Delays due to suboptimal routing paths',
      severity: analysisData.routingLevel || 'low',
      percentage: analysisData.routingPercentage || 10,
      icon: <CheckIcon />,
      color: theme.palette.success.main,
    },
    {
      type: 'Retransmissions',
      description: 'Delays caused by packet retransmissions',
      severity: analysisData.retransmissionLevel || 'high',
      percentage: analysisData.retransmissionPercentage || 50,
      icon: <ErrorIcon />,
      color: theme.palette.error.main,
    },
  ];

  const getSeverityColor = (severity) => {
    const colors = {
      low: theme.palette.success.main,
      medium: theme.palette.warning.main,
      high: theme.palette.error.main,
    };
    return colors[severity] || theme.palette.info.main;
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Delay Categorization
      </Typography>

      <Grid container spacing={3}>
        {delayCategories.map((category) => (
          <Grid item xs={12} key={category.type}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <Box sx={{ color: category.color, mr: 1 }}>
                    {category.icon}
                  </Box>
                  <Typography variant="h6">
                    {category.type}
                  </Typography>
                  <Chip
                    label={category.severity.toUpperCase()}
                    size="small"
                    sx={{
                      ml: 2,
                      backgroundColor: getSeverityColor(category.severity),
                      color: 'white',
                    }}
                  />
                </Box>

                <Typography color="textSecondary" gutterBottom>
                  {category.description}
                </Typography>

                <Box sx={{ display: 'flex', alignItems: 'center', mt: 2 }}>
                  <Box sx={{ flex: 1, mr: 2 }}>
                    <LinearProgress
                      variant="determinate"
                      value={category.percentage}
                      sx={{
                        height: 10,
                        borderRadius: 5,
                        backgroundColor: theme.palette.grey[200],
                        '& .MuiLinearProgress-bar': {
                          backgroundColor: category.color,
                          borderRadius: 5,
                        },
                      }}
                    />
                  </Box>
                  <Typography variant="body2" color="textSecondary">
                    {category.percentage}%
                  </Typography>
                </Box>

                <Box sx={{ mt: 2 }}>
                  <Typography variant="body2" color="textSecondary">
                    {category.insights || 'No specific insights available for this category.'}
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
};

export default DelayCategories;
