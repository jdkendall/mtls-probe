package com.jdkendall.mtls.probe.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.SSLContext;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "client.config")
public class AppConfiguration {
    private Map<String, ClientConfig> targets;

    public Map<String, ClientConfig> getTargets() {
        return targets;
    }

    public void setTargets(Map<String, ClientConfig> targets) {
        this.targets = targets;
    }

    @Bean
    public SSLContext defaultSslContext() throws NoSuchAlgorithmException {
        return SSLContext.getDefault();
    }
}
