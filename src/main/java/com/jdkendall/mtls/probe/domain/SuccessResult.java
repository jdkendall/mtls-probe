package com.jdkendall.mtls.probe.domain;

public class SuccessResult extends ProbeResult {
    private final int status;

    public SuccessResult(String target, int status) {
        super(target);
        this.status = status;
    }

    public int getStatus() {
        return status;
    }

    @Override
    public boolean isSuccess() {
        return true;
    }

    @Override
    public String toString() {
        return "SuccessResult{" +
                "status=" + status +
                ", target='" + getTarget() + '\'' +
                '}';
    }
}
