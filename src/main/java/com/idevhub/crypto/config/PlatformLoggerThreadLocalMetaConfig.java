package com.idevhub.crypto.config;

import com.idevhub.protocol.platform.service.PlatformLogger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PlatformLoggerThreadLocalMetaConfig {

    @Bean
    public ThreadLocal<PlatformLogger.Meta> getMeta() {
        return new ThreadLocal<>();
    }
}
