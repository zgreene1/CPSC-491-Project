import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import { Dashboard } from "./pages/Dashboard";
import { Login } from "./pages/Login";
import { NewScan } from "./pages/NewScan";
import { Reports } from "./pages/Reports";
import { ScanHistory } from "./pages/ScanHistory";
import { ScanProgress } from "./pages/ScanProgress";
import { ScanResults } from "./pages/ScanResults";
import { Settings } from "./pages/Settings";
import { ProtectedRoute } from "./routes/ProtectedRoute";

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />

      <Route
        element={
          <ProtectedRoute>
            <AppShell />
          </ProtectedRoute>
        }
      >
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scans/new" element={<NewScan />} />
        <Route path="/scans/:scanId/progress" element={<ScanProgress />} />
        <Route path="/scans/:scanId/results" element={<ScanResults />} />
        <Route path="/history" element={<ScanHistory />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
      </Route>

      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
