package com.jdkendall.mtls.probe.config;

public record ClientConfig(String url, String expectedStatus, String expectedContent) {
}
