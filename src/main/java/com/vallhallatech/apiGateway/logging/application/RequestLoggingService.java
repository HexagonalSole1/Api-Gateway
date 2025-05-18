package com.vallhallatech.apiGateway.logging.application;


import com.vallhallatech.apiGateway.logging.domain.RequestLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

@Service
public class RequestLoggingService {

    private static final Logger logger = LoggerFactory.getLogger(RequestLoggingService.class);

    public void logIncomingRequest(RequestLog requestLog) {
        try {
            // Configurar MDC para logging estructurado
            MDC.put("requestId", requestLog.getRequestId());
            MDC.put("userId", requestLog.getUserId());
            MDC.put("clientIp", requestLog.getClientIp());

            logger.info("Incoming request: {} {} from {} (user: {})",
                    requestLog.getMethod(),
                    requestLog.getPath(),
                    requestLog.getClientIp(),
                    requestLog.getUserId());
        } finally {
            MDC.clear();
        }
    }

    public void logOutgoingResponse(String requestId, int statusCode, long durationMs, String targetService) {
        try {
            MDC.put("requestId", requestId);
            MDC.put("targetService", targetService);
            MDC.put("duration", String.valueOf(durationMs));

            logger.info("Response: {} -> {} ({}ms) to {}",
                    requestId, statusCode, durationMs, targetService);
        } finally {
            MDC.clear();
        }
    }

    public void logError(String requestId, String error, Throwable throwable) {
        try {
            MDC.put("requestId", requestId);
            logger.error("Error processing request {}: {}", requestId, error, throwable);
        } finally {
            MDC.clear();
        }
    }
}