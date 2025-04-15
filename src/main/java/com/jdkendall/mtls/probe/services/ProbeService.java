package com.jdkendall.mtls.probe.services;

import com.jdkendall.mtls.probe.config.AppConfiguration;
import com.jdkendall.mtls.probe.config.ClientConfig;
import com.jdkendall.mtls.probe.domain.FailResult;
import com.jdkendall.mtls.probe.domain.ProbeResult;
import com.jdkendall.mtls.probe.domain.SuccessResult;
import org.apache.hc.client5.http.fluent.Request;
import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.*;
import java.util.HashMap;
import java.util.Map;

@Service
public class ProbeService {

    private static final Logger LOG = LoggerFactory.getLogger(ProbeService.class);
    private final AppConfiguration config;
    private final SSLContext sslContext;

    public ProbeService(AppConfiguration config, SSLContext sslContext) {
        this.config = config;
        this.sslContext = sslContext;
    }

    public Map<String, ProbeResult> verify() {
        Map<String, ProbeResult> results = new HashMap<>();
        for (var target : config.getTargets().entrySet()) {
            String targetKey = target.getKey();
            try {
                LOG.info("Verifying connection to: {}", targetKey);

                try (var client = createClient(this.sslContext)) {
                    HttpResponse response = Request.head(target.getValue().url())
                            .connectTimeout(Timeout.ofMilliseconds(1000))
                            .responseTimeout(Timeout.ofMilliseconds(1000))
                            .execute(client)
                            .returnResponse();

                    int status = response.getCode();
                    System.out.println("HTTP status: " + status);
                    results.put(targetKey, new SuccessResult(targetKey, status));
                }
            } catch (Exception e) {
                results.put(targetKey, interpretError(targetKey, target.getValue(), e));
            }
        }

        return results;
    }

    private FailResult interpretError(String targetId, ClientConfig ignoredTargetConfig, Exception e) {
        LOG.error("Error connecting to [{}]:", targetId, e);
        String error = "", recommendation = "";
        switch (e) {
            case java.net.UnknownHostException ex -> {
                error = "Unknown host: %s".formatted(ex.getMessage());
                recommendation = "Recommended course of action: Verify the URL provided is correct and try again. " +
                        "If the URL is correct, ensure the DNS resolution is working properly.";
            }
            case java.net.ConnectException ex -> {
                error = "Connection refused: %s".formatted(ex.getMessage());
                recommendation = "Recommended course of action: Ensure the target server is running and accessible.";
            }
            case java.net.SocketTimeoutException ex -> {
                error = "Connection timed out: %s".formatted(ex.getMessage());
                recommendation = "Recommended course of action: Ensure the target server is running and accessible. " +
                        "If running, then check network connectivity and firewall from container to target server.";
            }
            case SSLHandshakeException ex -> {
                error = "SSL handshake error: %s".formatted(ex.getMessage());
                recommendation = interpretSSLHandshakeError(ex);
            }
            case java.io.IOException ex -> {
                error = "I/O error: %s".formatted(ex.getMessage());
                recommendation = "Recommended course of action: Check the target server's response and ensure it's reachable.";
            }
            case null -> {
                error = "Unknown error (null exception reported)";
                recommendation = "Recommended course of action: Contact application support team.";
            }
            default -> {
                error = e.getMessage();
                recommendation = "Recommended course of action: Contact application support team.";
            }
        }
        LOG.error(error);
        LOG.error(recommendation);
        return new FailResult(targetId, error, recommendation);
    }

    private String interpretSSLHandshakeError(SSLHandshakeException ex) {
        String rec = "Contact application support team";

        if (ex.getCause() != null) {
            rec = switch (ex.getCause()) {
                case CertificateException cex -> interpretCertificateException(cex);
                case NoSuchAlgorithmException ignored -> "The target server requires a cryptographic algorithm not supported by this application. Contact the application support team.";
                case KeyStoreException ignored -> "The application cannot access the configured keystore. Contact the application support team.";
                case UnrecoverableKeyException ignored -> "The application cannot access a key in the configured keystore due to invalid password or corruption. Contact the application support team.";
                case NoSuchProviderException ignored -> "The application could not find the specified security provider. Contact the application support team.";
                case SSLException ignored -> "A generic SSL/TLS failure occurred during handshake with the target server. Possible causes include protocol mismatch, cipher suite incompatibility, or cert validation errors. Contact the application support team to verify the SSL/TLS configuration against the target server.";
                default -> rec;
            };
        } else {
            rec = switch (ex.getMessage()) {
                case "Received fatal alert: certificate_required" ->
                        "Target server requires an mTLS connection, and the application did not send a valid mTLS client certificate. Verify application is configured to send the correct mTLS client certificate from its keystore.";
                case "Received fatal alert: protocol_version" ->
                        "Target server requires a protocol of TLS not supported by this application. Contact the application support team.";
                case null, default -> rec;
            };
        }

        return "Recommended course of action: %s".formatted(rec);
    }

    private String interpretCertificateException(CertificateException cex) {
        return switch (cex) {
            case CertificateEncodingException ignored ->
                    "The target server presented a malformed certificate. Contact the target server's support team to investigate.";
            case CertificateExpiredException ignored ->
                    "The target server presented an expired certificate. Contact the target server's support team to renew the certificate.";
            case CertificateParsingException ignored ->
                    "The target server presented a malformed certificate containing bad formatting or invalid fields. Contact the target server's support team.";
            case CertificateRevokedException ignored ->
                    "The target server presented an explicitly revoked certificate. Contact the target server's support team to investigate.";
            case CertificateNotYetValidException ignored ->
                    "The target server presented a certificate that is not yet valid. Verify the system clock for the application is correct. If correct, then contact the target server's support team to resolve.";
            case null -> "Contact application support team";
            default -> {
                if (cex.getCause() != null) {
                    yield switch (cex.getCause()) {
                        case CertPathBuilderException cpbex -> interpretCertPathBuilderException(cpbex);
                        case CertPathValidatorException cpvex -> interpretCertPathValidatorException(cpvex);
                        default -> interpretOtherCertificateExceptionCause(cex.getCause());
                    };
                } else {
                    yield "Contact application support team";
                }
            }
        };
    }

    private String interpretOtherCertificateExceptionCause(Throwable ex) {
        return "Contact application support team";
    }

    private String interpretCertPathBuilderException(CertPathBuilderException cpbex) {
        return switch(cpbex.getMessage()) {
            case "unable to find valid certification path to requested target",
                 "SunCertPathBuilderException: unable to find valid certification path" -> "The target server has provided a certificate that is not trusted by the application. Verify that the latest certificates for the target server are added to the application truststore. If correct, then next verify the target server is reporting the correct certificates. If both are correct, then contact application support team.";
            case "No trusted certificate found" -> "Target server appears to be using a self-signed or unsigned certificate. Verify that the target server is reporting the correct certificates. If so, then verify with the target server's support team that these certificates should be trusted, and add to the application's trust store.";
            case null, default -> "Contact application support team";
        };
    }

    private String interpretCertPathValidatorException(CertPathValidatorException cpvex) {
        return switch (cpvex.getCause()) {
            case CertificateException cex -> interpretCertificateException(cex);
            case null, default -> "Contact application support team";
        };
    }

    private static CloseableHttpClient createClient(SSLContext sslContext) {
        SSLConnectionSocketFactory socketFactory = SSLConnectionSocketFactoryBuilder.create()
                .setSslContext(sslContext)
                .build();

        HttpClientConnectionManager connManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(socketFactory)
                .build();

        return HttpClients.custom()
                .setConnectionManager(connManager)
                .evictExpiredConnections()
                .setRetryStrategy(new DefaultHttpRequestRetryStrategy(1, TimeValue.ofMilliseconds(100)))
                .build();
    }
}
