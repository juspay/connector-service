import { useState, useMemo } from "react";
import {
  Play,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  GitBranch,
  Database,
} from "lucide-react";
import { DiffEditor } from "@monaco-editor/react";
import stringify from "json-stable-stringify";

export default function ReplayResults({ data }) {
  const [selectedId, setSelectedId] = useState(null);
  const [replayResults, setReplayResults] = useState({});
  const [loading, setLoading] = useState({});

  function normalizeJson(json) {
    if (!json) return json; // fallback

    return stringify(json, {
      space: 2,
      cmp: (a, b) => a.key.localeCompare(b.key),
    });
  }

  function formatDateTime(ms) {
    const d = new Date(ms);

    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }
  const selectedRecording = useMemo(
    () => data?.find((r) => r.request_id === selectedId),
    [data, selectedId]
  );

  const handleReplay = async (recording) => {
    setLoading((p) => ({ ...p, [recording.request_id]: true }));
    try {
      const res = await fetch(
        `http://localhost:8000/replay?recording_id=${recording.id}`,
        { method: "POST" }
      );
      const json = await res.json();
      setReplayResults((p) => ({ ...p, [recording.request_id]: json }));
    } catch (e) {
      setReplayResults((p) => ({
        ...p,
        [recording.request_id]: { error: e.message },
      }));
    } finally {
      setLoading((p) => ({ ...p, [recording.request_id]: false }));
    }
  };

  const statusConfig = (id) => {
    const r = replayResults[id];
    if (!r)
      return {
        label: "Not replayed",
        color: "text-gray-500",
        Icon: Clock,
      };
    if (r.error)
      return { label: "Error", color: "text-red-600", Icon: XCircle };
    if (r.summary?.failed)
      return { label: "Failed", color: "text-red-600", Icon: XCircle };
    if (r.summary?.changed)
      return {
        label: "Changed",
        color: "text-yellow-600",
        Icon: AlertCircle,
      };
    return {
      label: "Identical",
      color: "text-green-600",
      Icon: CheckCircle,
    };
  };

  return (
    <div className="min-h-screen bg-gray-50 p-6 font-sans">
      <div className="grid grid-cols-[360px_1fr] gap-6">
        {/* LEFT – RECORDINGS LIST */}
        <aside className="recording-list">

          <div className="max-h-[calc(100vh-140px)] overflow-y-auto">
            {data.map((r) => {
              const { Icon, label } = statusConfig(r.request_id);
              const isActive = selectedId === r.request_id;

              return (
                <div
                  key={r.request_id}
                  onClick={() => setSelectedId(r.request_id)}
                  className={`recording-row ${isActive ? "active" : ""}`}
                >
                  <div className="recording-main">
                    <div className="recording-title">
                      {r.method}
                    </div>
                    <div className="recording-subtitle">
                      {r.authority} · {formatDateTime(r.start_ms)} · {r.end_ms - r.start_ms}ms
                    </div>
                  </div>

                  <div className="recording-meta">
                    <span
                      className={`recording-status ${label === "Identical"
                        ? "status-identical"
                        : label === "Changed"
                          ? "status-changed"
                          : label === "Failed"
                            ? "status-failed"
                            : "status-pending"
                        }`}
                    >
                      <Icon className="w-3 h-3" />
                      {label}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </aside>


        {/* RIGHT – DETAILS */}
        <main className="bg-white border rounded-lg min-h-[500px]">
          {!selectedRecording ? (
            <div className="h-full flex items-center justify-center text-gray-400">
              Select a recording to view details
            </div>
          ) : (
            <div className="flex flex-col h-full">
              {/* HEADER */}
              <div className="px-6 py-4 border-b flex items-center justify-between">
                <div>
                  <h2 className="font-semibold font-mono">
                    {selectedRecording.method}
                  </h2>
                  <div className="text-xs text-gray-500">
                    {selectedRecording.request_id}
                  </div>
                </div>
                <button
                  onClick={() => handleReplay(selectedRecording)}
                  disabled={loading[selectedRecording.request_id]}
                  className="flex items-center gap-2 px-3 py-1.5 text-sm bg-black text-white rounded hover:bg-gray-800"
                >
                  <Play className="w-4 h-4" />
                  {loading[selectedRecording.request_id]
                    ? "Replaying…"
                    : "Replay"}
                </button>
              </div>

              {/* DIFF */}
              <div className="flex-1 overflow-auto p-6">
                {replayResults[selectedRecording.request_id]?.error && (
                  <div className="text-red-600">
                    {replayResults[selectedRecording.request_id].error}
                  </div>
                )}

                {replayResults[selectedRecording.request_id]?.results?.map(
                  (res, i) => (
                    <div key={i} className="mb-8">
                      <div className="mb-2 flex items-center gap-2 text-sm">
                        <GitBranch className="w-4 h-4" />
                        Level: {res.level} · Status: {res.semantic?.status}
                      </div>

                      {res.expected && res.actual && (
                        <div className="h-[600px] border rounded-lg overflow-hidden">
                          <DiffEditor
                            original={normalizeJson(res.expected)}   // LEFT
                            modified={normalizeJson(res.actual)}     // RIGHT
                            language="json"
                            theme="vs"
                            options={{
                              readOnly: true,
                              renderSideBySide: true,
                              wordWrap: "on",                 // 👈 NO horizontal scroll
                              minimap: { enabled: false },
                              scrollBeyondLastLine: false,
                              automaticLayout: true,
                              renderOverviewRuler: false,
                              diffAlgorithm: "advanced",
                            }}
                          />
                        </div>

                      )}
                    </div>
                  )
                )}
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
