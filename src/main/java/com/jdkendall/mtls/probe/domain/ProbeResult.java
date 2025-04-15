package com.jdkendall.mtls.probe.domain;

public abstract class ProbeResult {
    private final String target;

    protected ProbeResult(String target) {
        this.target = target;
    }

    public String getTarget() {
        return target;
    }

    public abstract boolean isSuccess();
}

