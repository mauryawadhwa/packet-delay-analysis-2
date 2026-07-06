import React, { createContext, useState, useContext, useEffect } from 'react';

const AnalysisContext = createContext();

export const useAnalysis = () => {
  return useContext(AnalysisContext);
};

export const AnalysisProvider = ({ children }) => {
  const [analysisData, setAnalysisData] = useState(() => {
    // Try to restore from sessionStorage on initial load
    const saved = sessionStorage.getItem('analysisData');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        console.error('Failed to parse analysisData from sessionStorage', e);
        return null;
      }
    }
    return null;
  });

  // Whenever analysisData changes, save it to sessionStorage
  useEffect(() => {
    if (analysisData) {
      sessionStorage.setItem('analysisData', JSON.stringify(analysisData));
    } else {
      sessionStorage.removeItem('analysisData');
    }
  }, [analysisData]);

  return (
    <AnalysisContext.Provider value={{ analysisData, setAnalysisData }}>
      {children}
    </AnalysisContext.Provider>
  );
};
