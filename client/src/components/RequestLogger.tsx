import React, { useState } from 'react';
import { RequestLog } from '../../../shared/types';

interface RequestLoggerProps {
  logs: RequestLog[];
  onClear: () => void;
}

const RequestLogger: React.FC<RequestLoggerProps> = ({ logs, onClear }) => {
  const [selectedLog, setSelectedLog] = useState<RequestLog | null>(null);

  const formatTimestamp = (timestamp: number) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const formatJson = (obj: any) => {
    try {
      return JSON.stringify(obj, null, 2);
    } catch {
      return String(obj);
    }
  };

  return (
    <div className="request-logger">
      <div className="logger-header">
        <h3>Requisições HTTP</h3>
        <button onClick={onClear} className="clear-btn">
          Limpar Logs
        </button>
      </div>

      <div className="logs-container">
        {logs.length === 0 ? (
          <div className="empty-logs">
            <p>Nenhuma requisição realizada ainda.</p>
            <p>Execute um fluxo OAuth para ver as requisições aqui.</p>
          </div>
        ) : (
          <>
            <div className="logs-list">
              {logs.map((log) => (
                <div
                  key={log.id}
                  className={`log-item ${selectedLog?.id === log.id ? 'selected' : ''}`}
                  onClick={() => setSelectedLog(log)}
                >
                  <div className="log-summary">
                    <span className={`method ${log.method.toLowerCase()}`}>
                      {log.method}
                    </span>
                    <span className="url">{log.url}</span>
                    <span className="time">{formatTimestamp(log.timestamp)}</span>
                    {log.status && (
                      <span className={`status status-${Math.floor(log.status / 100)}xx`}>
                        {log.status}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {selectedLog && (
              <div className="log-details">
                <h4>Detalhes da Requisição</h4>
                
                <div className="detail-section">
                  <h5>Requisição</h5>
                  <div className="request-info">
                    <p><strong>Método:</strong> {selectedLog.method}</p>
                    <p><strong>URL:</strong> {selectedLog.url}</p>
                    <p><strong>Timestamp:</strong> {new Date(selectedLog.timestamp).toLocaleString()}</p>
                  </div>
                  
                  <div className="headers">
                    <h6>Headers:</h6>
                    <pre>{formatJson(selectedLog.headers)}</pre>
                  </div>

                  {selectedLog.body && (
                    <div className="body">
                      <h6>Body:</h6>
                      <pre>{formatJson(selectedLog.body)}</pre>
                    </div>
                  )}
                </div>

                {selectedLog.response && (
                  <div className="detail-section">
                    <h5>Resposta</h5>
                    {selectedLog.status && (
                      <p><strong>Status:</strong> {selectedLog.status}</p>
                    )}
                    <div className="response">
                      <h6>Response Body:</h6>
                      <pre>{formatJson(selectedLog.response)}</pre>
                    </div>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default RequestLogger;
