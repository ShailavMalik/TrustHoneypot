import { Routes, Route, Navigate } from "react-router-dom";
import Landing from "./pages/Landing";
import Dashboard from "./pages/Dashboard";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route
        path="/about"
        element={<Navigate to="/dashboard/about" replace />}
      />
      <Route path="/dashboard/*" element={<Dashboard />} />
    </Routes>
  );
}
