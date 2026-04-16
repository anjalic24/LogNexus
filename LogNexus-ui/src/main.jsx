import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { ThemeProvider } from './contexts/ThemeContext.jsx'
import { ActiveBundleProvider } from './contexts/ActiveBundleContext.jsx'
import './index.css'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ThemeProvider>
      <ActiveBundleProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </ActiveBundleProvider>
    </ThemeProvider>
  </StrictMode>,
)
