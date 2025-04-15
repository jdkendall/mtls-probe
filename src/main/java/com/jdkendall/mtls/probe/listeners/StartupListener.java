package com.jdkendall.mtls.probe.listeners;

import com.jdkendall.mtls.probe.domain.FailResult;
import com.jdkendall.mtls.probe.domain.SuccessResult;
import com.jdkendall.mtls.probe.services.ProbeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class StartupListener {
    private final ProbeService probeService;

    public StartupListener(ProbeService probeService) {
        this.probeService = probeService;
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        LOG.info("Application started: {}", event.getTimestamp());

        probeService.verify().forEach((id, res) -> {
            if (res.isSuccess()) {
                LOG.info("Probe [{}] succeeded with status [{}]", id, ((SuccessResult)res).getStatus());
            } else {
                FailResult failResult = (FailResult) res;
                LOG.error("Probe [{}] failed with error [{}] and recommendation [{}]", id, failResult.getError(), failResult.getRecommendation());
            }
        });
    }

    private static final Logger LOG = LoggerFactory.getLogger(StartupListener.class);
}
