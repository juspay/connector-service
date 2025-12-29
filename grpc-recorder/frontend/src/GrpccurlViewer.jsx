import { useState } from "react";
import { Copy, Terminal, ChevronDown, ChevronUp, Code, FileJson } from "lucide-react";

export default function GrpccurlViewer({ recording }) {
  const [showRequest, setShowRequest] = useState(true);
  const [showResponse, setShowResponse] = useState(true);
  const [responseView, setResponseView] = useState("decoded"); // "raw" or "decoded"

  if (!recording) {
    return (
      <div className="p-4 text-gray-500 text-center">
        Select a recording to view grpccurl format
      </div>
    );
  }

  // Generate grpccurl command for the request
  const generateGrpccurlCommand = () => {
    const { method, authority, request, headers } = recording;
    
    // Extract service and method from the full method name
    const [service, methodName] = method.split('/').filter(Boolean);
    
    // Create a copy of request without the 'headers' field
    const { headers: _, ...requestWithoutHeaders } = request || {};
    
    // Format the request body as a single line JSON for terminal compatibility
    const requestBody = Object.keys(requestWithoutHeaders).length > 0 
      ? JSON.stringify(requestWithoutHeaders) 
      : '{}';
    
    // Build the command with proper escaping
    let command = `grpcurl -plaintext`;
    
    // Add headers if they exist (as metadata, not in request body)
    if (headers && Object.keys(headers).length > 0) {
      Object.entries(headers).forEach(([key, value]) => {
        command += ` \\\n  -H '${key}: ${value}'`;
      });
    }
    
    // Add the request data (without headers)
    command += ` \\\n  -d '${requestBody.replace(/'/g, "'\"'\"'")}'`;
    
    // Add the service endpoint
    command += ` \\\n  ${authority}:${recording.port || 50051}`;
    command += ` \\\n  ${service}/${methodName}`;
    
    return command;
  };

  // Decode base64 response
  const decodeBase64 = (str) => {
    try {
      return atob(str);
    } catch {
      return str;
    }
  };

  // Try to parse response as JSON
  const tryParseJson = (str) => {
    try {
      const parsed = JSON.parse(str);
      return JSON.stringify(parsed, null, 2);
    } catch {
      return str;
    }
  };

  // Format response for display
  const formatResponse = () => {
    const { response } = recording;
    if (!response) return 'No response data available';
    
    // If response is already an object, stringify it
    if (typeof response === 'object') {
      return JSON.stringify(response, null, 2);
    }
    
    // If response is a string, try to decode and parse
    if (typeof response === 'string') {
      // Check if it's base64 encoded
      const isBase64 = /^[A-Za-z0-9+/]+=*$/.test(response) && response.length % 4 === 0;
      
      if (isBase64) {
        const decoded = decodeBase64(response);
        return tryParseJson(decoded);
      }
      
      // Try to parse as JSON directly
      return tryParseJson(response);
    }
    
    return String(response);
  };

  // Get raw response
  const getRawResponse = () => {
    const { response } = recording;
    if (!response) return 'No response data available';
    
    if (typeof response === 'object') {
      return JSON.stringify(response);
    }
    
    return String(response);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const grpccurlCommand = generateGrpccurlCommand();
  const formattedResponse = formatResponse();
  const rawResponse = getRawResponse();

  return (
    <div className="bg-gray-900 text-gray-100 font-mono text-sm">
      {/* REQUEST SECTION */}
      <div className="border-b border-gray-700">
        <div 
          className="flex items-center justify-between px-4 py-3 bg-gray-800 cursor-pointer hover:bg-gray-750"
          onClick={() => setShowRequest(!showRequest)}
        >
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-green-400" />
            <span className="text-green-400 font-semibold">REQUEST (grpcurl)</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={(e) => {
                e.stopPropagation();
                copyToClipboard(grpccurlCommand);
              }}
              className="p-1 hover:bg-gray-700 rounded"
              title="Copy command"
            >
              <Copy className="w-4 h-4" />
            </button>
            {showRequest ? (
              <ChevronUp className="w-4 h-4" />
            ) : (
              <ChevronDown className="w-4 h-4" />
            )}
          </div>
        </div>
        
        {showRequest && (
          <div className="p-4 bg-gray-900">
            <pre className="whitespace-pre-wrap break-all">
              <code className="text-gray-100">{grpccurlCommand}</code>
            </pre>
          </div>
        )}
      </div>

      {/* RESPONSE SECTION */}
      <div>
        <div 
          className="flex items-center justify-between px-4 py-3 bg-gray-800 cursor-pointer hover:bg-gray-750"
          onClick={() => setShowResponse(!showResponse)}
        >
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-blue-400" />
            <span className="text-blue-400 font-semibold">RESPONSE</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={(e) => {
                e.stopPropagation();
                copyToClipboard(responseView === "decoded" ? formattedResponse : rawResponse);
              }}
              className="p-1 hover:bg-gray-700 rounded"
              title="Copy response"
            >
              <Copy className="w-4 h-4" />
            </button>
            {showResponse ? (
              <ChevronUp className="w-4 h-4" />
            ) : (
              <ChevronDown className="w-4 h-4" />
            )}
          </div>
        </div>
        
        {showResponse && (
          <div className="bg-gray-900">
            {/* Response View Toggle */}
            <div className="flex border-b border-gray-700">
              <button
                onClick={() => setResponseView("decoded")}
                className={`flex items-center gap-2 px-4 py-2 text-xs font-medium transition-colors ${
                  responseView === "decoded"
                    ? "bg-gray-800 text-blue-400 border-b-2 border-blue-400"
                    : "text-gray-400 hover:text-gray-200"
                }`}
              >
                <FileJson className="w-3 h-3" />
                Decoded
              </button>
              <button
                onClick={() => setResponseView("raw")}
                className={`flex items-center gap-2 px-4 py-2 text-xs font-medium transition-colors ${
                  responseView === "raw"
                    ? "bg-gray-800 text-blue-400 border-b-2 border-blue-400"
                    : "text-gray-400 hover:text-gray-200"
                }`}
              >
                <Code className="w-3 h-3" />
                Raw
              </button>
            </div>
            
            {/* Response Content */}
            <div className="p-4">
              <pre className="whitespace-pre-wrap break-all">
                <code className="text-gray-100">
                  {responseView === "decoded" ? formattedResponse : rawResponse}
                </code>
              </pre>
            </div>
          </div>
        )}
      </div>

      {/* METADATA */}
      <div className="border-t border-gray-700 px-4 py-3 bg-gray-800">
        <div className="grid grid-cols-2 gap-4 text-xs">
          <div>
            <span className="text-gray-400">Method:</span>
            <span className="ml-2 text-gray-200">{recording.method}</span>
          </div>
          <div>
            <span className="text-gray-400">Authority:</span>
            <span className="ml-2 text-gray-200">{recording.authority}</span>
          </div>
          <div>
            <span className="text-gray-400">Request ID:</span>
            <span className="ml-2 text-gray-200">{recording.request_id}</span>
          </div>
          <div>
            <span className="text-gray-400">Duration:</span>
            <span className="ml-2 text-gray-200">{recording.end_ms - recording.start_ms}ms</span>
          </div>
        </div>
      </div>
    </div>
  );
}
