package com.jdkendall.mtls.probe.domain;

public class FailResult extends ProbeResult {
    private final String error;
    private final String recommendation;

    public FailResult(String target, String error, String recommendation) {
        super(target);
        this.error = error;
        this.recommendation = recommendation;
    }

    public String getError() {
        return error;
    }

    public String getRecommendation() {
        return recommendation;
    }

    @Override
    public boolean isSuccess() {
        return false;
    }

    @Override
    public String toString() {
        return "FailResult{" +
                "error='" + error + '\'' +
                ", recommendation='" + recommendation + '\'' +
                ", target='" + getTarget() + '\'' +
                '}';
    }
}
