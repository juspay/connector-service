import { Navigate, Route, Routes } from "react-router-dom";
import { Homepage } from "./pages/Homepage";
import { WorkflowPage } from "./pages/WorkflowPage";

/**
 * App shell. Two routes for now:
 *   /                       — Homepage (sessions list, create)
 *   /sessions/:sessionId    — WorkflowPage (per-session pipeline UI)
 *
 * Anything unmatched bounces to "/" so the back-button never strands the
 * user on a dead URL after a session is deleted.
 */
export function App() {
  return (
    <Routes>
      <Route path="/" element={<Homepage />} />
      <Route path="/sessions/:sessionId" element={<WorkflowPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
