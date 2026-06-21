import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

// Apply the saved theme before first paint to avoid a flash of the wrong theme.
document.documentElement.setAttribute(
  'data-theme',
  localStorage.getItem('ego-theme') === 'light' ? 'light' : 'dark',
);

const container = document.getElementById('root');
if (!container) throw new Error('Root element not found');

const root = createRoot(container);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
