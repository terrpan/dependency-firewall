import { RouterProvider } from 'react-router-dom'
import { AppProviders } from './app/providers.tsx'
import { router } from './app/router.tsx'

function App() {
  return (
    <AppProviders>
      <RouterProvider router={router} />
    </AppProviders>
  )
}

export default App
