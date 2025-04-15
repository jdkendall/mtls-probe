package com.jdkendall.mtls.probe;

import com.jdkendall.mtls.probe.config.AppConfiguration;
import com.jdkendall.mtls.probe.config.ClientConfig;
import com.jdkendall.mtls.probe.domain.FailResult;
import com.jdkendall.mtls.probe.domain.ProbeResult;
import com.jdkendall.mtls.probe.domain.SuccessResult;
import com.jdkendall.mtls.probe.services.ProbeService;
import org.apache.hc.core5.ssl.SSLContexts;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class ProbeServiceTest {
    private static final String TEST_RESOURCES_PATH = "src/test/resources/";

    @Test
    void testWithNoClientCert() throws Exception {
        ImageFromDockerfile image = new ImageFromDockerfile("mtls-httpd-testserver", true)
                .withDockerfile(Path.of(TEST_RESOURCES_PATH, "properlyConfiguredServer-Dockerfile"));

        try (GenericContainer<?> httpd = new GenericContainer<>(image).withExposedPorts(443)
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("httpd")))
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(1)))) {
            httpd.start();

            int port = httpd.getMappedPort(443);
            String url = "https://" + httpd.getHost() + ":" + port + "/test";

            System.out.println("Server started on port: " + port);
            System.out.println("Calculated URL is: " + url);

            // Create client WITHOUT key material (no cert) using truststore from test resources folder
            File clientTruststoreFile = new File(TEST_RESOURCES_PATH + "certs/client/client-truststore.jks");
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(clientTruststoreFile, "changeit".toCharArray())
                    .build();

            AppConfiguration config = new AppConfiguration();
            config.setTargets(Map.of("test", new ClientConfig(url, "200", "mTLS with Apache OK")));

            ProbeService testee = new ProbeService(config, sslContext);

            Map<String, ProbeResult> results = testee.verify();
            ProbeResult result = results.get("test");
            assertFalse(result.isSuccess());

            FailResult failResult = (FailResult) result;
            assertEquals("SSL handshake error: Received fatal alert: certificate_required", failResult.getError());
            assertEquals("Recommended course of action: Target server requires an mTLS connection, and the application did not send a valid mTLS client certificate. Verify application is configured to send the correct mTLS client certificate from its keystore.", failResult.getRecommendation());
        }
    }

    @Test
    void testWithAlienClientCert() throws Exception {
        ImageFromDockerfile image = new ImageFromDockerfile("mtls-httpd-testserver", true)
                .withDockerfile(Path.of(TEST_RESOURCES_PATH, "properlyConfiguredServer-Dockerfile"));

        try (GenericContainer<?> httpd = new GenericContainer<>(image).withExposedPorts(443)
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("httpd")))
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(1)))) {
            httpd.start();

            int port = httpd.getMappedPort(443);
            String url = "https://" + httpd.getHost() + ":" + port + "/test";

            System.out.println("Server started on port: " + port);
            System.out.println("Calculated URL is: " + url);

            // Create client with alien key material
            File clientTruststoreFile = new File(TEST_RESOURCES_PATH + "certs/client/client-truststore.jks");
            File clientKeystoreFile = new File(TEST_RESOURCES_PATH + "certs/alien-client/alien-client-keystore.jks");
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(clientTruststoreFile, "changeit".toCharArray())
                    .loadKeyMaterial(clientKeystoreFile, "changeit".toCharArray(), "changeit".toCharArray())
                    .build();

            AppConfiguration config = new AppConfiguration();
            config.setTargets(Map.of("test", new ClientConfig(url, "200", "mTLS with Apache OK")));

            ProbeService testee = new ProbeService(config, sslContext);

            Map<String, ProbeResult> results = testee.verify();
            ProbeResult result = results.get("test");
            assertFalse(result.isSuccess());

            FailResult failResult = (FailResult) result;
            assertEquals("SSL handshake error: Received fatal alert: certificate_required", failResult.getError());
            assertEquals("Recommended course of action: Target server requires an mTLS connection, and the application did not send a valid mTLS client certificate. Verify application is configured to send the correct mTLS client certificate from its keystore.", failResult.getRecommendation());
        }
    }

    @Test
    void testWithValidClientCert() throws Exception {
        ImageFromDockerfile image = new ImageFromDockerfile("mtls-httpd-testserver", true)
                .withDockerfile(Path.of(TEST_RESOURCES_PATH, "properlyConfiguredServer-Dockerfile"));

        try (GenericContainer<?> httpd = new GenericContainer<>(image).withExposedPorts(443)
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("httpd")))
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(1)))) {
            httpd.start();

            int port = httpd.getMappedPort(443);
            String url = "https://" + httpd.getHost() + ":" + port + "/test";

            System.out.println("Server started on port: " + port);
            System.out.println("Calculated URL is: " + url);

            // Create client with alien key material
            File clientTruststoreFile = new File(TEST_RESOURCES_PATH + "certs/client/client-truststore.jks");
            File clientKeystoreFile = new File(TEST_RESOURCES_PATH + "certs/client/client-keystore.jks");
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(clientTruststoreFile, "changeit".toCharArray())
                    .loadKeyMaterial(clientKeystoreFile, "changeit".toCharArray(), "changeit".toCharArray())
                    .build();

            AppConfiguration config = new AppConfiguration();
            config.setTargets(Map.of("test", new ClientConfig(url, "200", "mTLS with Apache OK")));

            ProbeService testee = new ProbeService(config, sslContext);

            Map<String, ProbeResult> results = testee.verify();
            ProbeResult result = results.get("test");
            assertTrue(result.isSuccess());

            SuccessResult successResult = (SuccessResult) result;
            assertEquals(200, successResult.getStatus());
        }
    }

    @Test
    void testWithExpiredServerCert() throws Exception {
        ImageFromDockerfile image = new ImageFromDockerfile("mtls-httpd-testserver", true)
                .withDockerfile(Path.of(TEST_RESOURCES_PATH, "expiredCertServer-Dockerfile"));

        try (GenericContainer<?> httpd = new GenericContainer<>(image).withExposedPorts(443)
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("httpd")))
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(1)))) {
            httpd.start();

            int port = httpd.getMappedPort(443);
            String url = "https://" + httpd.getHost() + ":" + port + "/test";

            System.out.println("Server started on port: " + port);
            System.out.println("Calculated URL is: " + url);

            // Create client with alien key material
            File clientTruststoreFile = new File(TEST_RESOURCES_PATH + "certs/client/client-truststore.jks");
            File clientKeystoreFile = new File(TEST_RESOURCES_PATH + "certs/client/client-keystore.jks");
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(clientTruststoreFile, "changeit".toCharArray())
                    .loadKeyMaterial(clientKeystoreFile, "changeit".toCharArray(), "changeit".toCharArray())
                    .build();

            AppConfiguration config = new AppConfiguration();
            config.setTargets(Map.of("test", new ClientConfig(url, "200", "mTLS with Apache OK")));

            ProbeService testee = new ProbeService(config, sslContext);

            Map<String, ProbeResult> results = testee.verify();
            ProbeResult result = results.get("test");
            assertFalse(result.isSuccess());

            FailResult failResult = (FailResult) result;
            assertEquals("SSL handshake error: PKIX path validation failed: java.security.cert.CertPathValidatorException: validity check failed", failResult.getError());
            assertEquals("Recommended course of action: The target server presented an expired certificate. Contact the target server's support team to renew the certificate.", failResult.getRecommendation());
        }
    }

    @Test
    void testWithBrokenServerCertChain() throws Exception {
        ImageFromDockerfile image = new ImageFromDockerfile("mtls-httpd-testserver", true)
                .withDockerfile(Path.of(TEST_RESOURCES_PATH, "brokenCertChainServer-Dockerfile"));

        try (GenericContainer<?> httpd = new GenericContainer<>(image).withExposedPorts(443)
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("httpd")))
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(1)))) {
            httpd.start();

            int port = httpd.getMappedPort(443);
            String url = "https://" + httpd.getHost() + ":" + port + "/test";

            System.out.println("Server started on port: " + port);
            System.out.println("Calculated URL is: " + url);

            // Create client with alien key material
            File clientTruststoreFile = new File(TEST_RESOURCES_PATH + "certs/client/client-truststore.jks");
            File clientKeystoreFile = new File(TEST_RESOURCES_PATH + "certs/client/client-keystore.jks");
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(clientTruststoreFile, "changeit".toCharArray())
                    .loadKeyMaterial(clientKeystoreFile, "changeit".toCharArray(), "changeit".toCharArray())
                    .build();

            AppConfiguration config = new AppConfiguration();
            config.setTargets(Map.of("test", new ClientConfig(url, "200", "mTLS with Apache OK")));

            ProbeService testee = new ProbeService(config, sslContext);

            Map<String, ProbeResult> results = testee.verify();
            ProbeResult result = results.get("test");
            assertFalse(result.isSuccess());

            FailResult failResult = (FailResult) result;
            assertEquals("SSL handshake error: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target", failResult.getError());
            assertEquals("Recommended course of action: The target server has provided a certificate that is not trusted by the application. Verify that the latest certificates for the target server are added to the application truststore. If correct, then next verify the target server is reporting the correct certificates. If both are correct, then contact application support team.", failResult.getRecommendation());
        }
    }

    @Test
    void testWithSelfSignedServerCert() throws Exception {
        ImageFromDockerfile image = new ImageFromDockerfile("mtls-httpd-testserver", true)
                .withDockerfile(Path.of(TEST_RESOURCES_PATH, "selfSignedServer-Dockerfile"));

        try (GenericContainer<?> httpd = new GenericContainer<>(image).withExposedPorts(443)
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("httpd")))
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(1)))) {
            httpd.start();

            int port = httpd.getMappedPort(443);
            String url = "https://" + httpd.getHost() + ":" + port + "/test";

            System.out.println("Server started on port: " + port);
            System.out.println("Calculated URL is: " + url);

            // Create client with alien key material
            File clientTruststoreFile = new File(TEST_RESOURCES_PATH + "certs/client/client-truststore.jks");
            File clientKeystoreFile = new File(TEST_RESOURCES_PATH + "certs/client/client-keystore.jks");
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(clientTruststoreFile, "changeit".toCharArray())
                    .loadKeyMaterial(clientKeystoreFile, "changeit".toCharArray(), "changeit".toCharArray())
                    .build();

            AppConfiguration config = new AppConfiguration();
            config.setTargets(Map.of("test", new ClientConfig(url, "200", "mTLS with Apache OK")));

            ProbeService testee = new ProbeService(config, sslContext);

            Map<String, ProbeResult> results = testee.verify();
            ProbeResult result = results.get("test");
            assertFalse(result.isSuccess());

            FailResult failResult = (FailResult) result;
            assertEquals("SSL handshake error: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target", failResult.getError());
            assertEquals("Recommended course of action: The target server has provided a certificate that is not trusted by the application. Verify that the latest certificates for the target server are added to the application truststore. If correct, then next verify the target server is reporting the correct certificates. If both are correct, then contact application support team.", failResult.getRecommendation());
        }
    }

    @Test
    void testWithNoMatchingProtocols() throws Exception {
        ImageFromDockerfile image = new ImageFromDockerfile("mtls-httpd-testserver", true)
                .withDockerfile(Path.of(TEST_RESOURCES_PATH, "properlyConfiguredServer-Dockerfile"));

        try (GenericContainer<?> httpd = new GenericContainer<>(image).withExposedPorts(443)
                .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger("httpd")))
                .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(1)))) {
            httpd.start();

            int port = httpd.getMappedPort(443);
            String url = "https://" + httpd.getHost() + ":" + port + "/test";

            System.out.println("Server started on port: " + port);
            System.out.println("Calculated URL is: " + url);

            // Create client with alien key material
            File clientTruststoreFile = new File(TEST_RESOURCES_PATH + "certs/client/client-truststore.jks");
            File clientKeystoreFile = new File(TEST_RESOURCES_PATH + "certs/client/client-keystore.jks");
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(clientTruststoreFile, "changeit".toCharArray())
                    .loadKeyMaterial(clientKeystoreFile, "changeit".toCharArray(), "changeit".toCharArray())
                    .setProtocol("TLSv1.2")
                    .build();

            AppConfiguration config = new AppConfiguration();
            config.setTargets(Map.of("test", new ClientConfig(url, "200", "mTLS with Apache OK")));

            ProbeService testee = new ProbeService(config, sslContext);

            Map<String, ProbeResult> results = testee.verify();
            ProbeResult result = results.get("test");
            assertFalse(result.isSuccess());

            FailResult failResult = (FailResult) result;
            assertEquals("SSL handshake error: Received fatal alert: protocol_version", failResult.getError());
            assertEquals("Recommended course of action: Target server requires a protocol of TLS not supported by this application. Contact the application support team.", failResult.getRecommendation());
        }
    }
}
