import { RouterProvider } from 'react-router-dom'
import { AppProviders } from './app/providers.tsx'
import { router } from './app/router.tsx'
import './App.css'

function App() {
  return (
    <AppProviders>
      <RouterProvider router={router} />
    </AppProviders>
  )
}

export default App
