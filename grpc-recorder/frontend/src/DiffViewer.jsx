import Editor from "@monaco-editor/react";

export default function DiffViewer({ original, modified, language = "json" }) {
  return (
    <Editor
      height="300px"
      theme="vs-dark"
      language={language}
      options={{
        readOnly: true,
        renderSideBySide: true,
        minimap: { enabled: false },
      }}
      original={original}
      modified={modified}
    />
  );
}
