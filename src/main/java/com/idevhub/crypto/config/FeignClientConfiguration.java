package com.idevhub.crypto.config;

import feign.Request;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FeignClientConfiguration {


    @Bean
    public Request.Options requestOptions() {
        return new Request.Options(120000, 120000);
    }

}
