package com.vallhallatech.apiGateway.logging.domain;

import java.time.LocalDateTime;
import java.util.Map;

public class RequestLog {
    private final String requestId;
    private final String method;
    private final String path;
    private final String clientIp;
    private final Map<String, String> headers;
    private final LocalDateTime timestamp;
    private final String userId;

    public RequestLog(String requestId, String method, String path, String clientIp,
                      Map<String, String> headers, String userId) {
        this.requestId = requestId;
        this.method = method;
        this.path = path;
        this.clientIp = clientIp;
        this.headers = Map.copyOf(headers);
        this.userId = userId;
        this.timestamp = LocalDateTime.now();
    }

    // Getters
    public String getRequestId() { return requestId; }
    public String getMethod() { return method; }
    public String getPath() { return path; }
    public String getClientIp() { return clientIp; }
    public Map<String, String> getHeaders() { return headers; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getUserId() { return userId; }

    @Override
    public String toString() {
        return String.format("[%s] %s %s from %s (user: %s) at %s",
                requestId, method, path, clientIp, userId, timestamp);
    }
}