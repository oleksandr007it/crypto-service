//package com.idevhub.feign;
//
//import com.idevhub.exceptions.CryptoServiceErrorDecoder;
//import feign.Request;
//import feign.codec.ErrorDecoder;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//public class CryptoServiceFeignConfiguration {
//    @Bean
//    public Request.Options requestOptions() {
//        return new Request.Options(180000, 180000);
//    }
//
//    @Bean
//    public ErrorDecoder createErrorDecoder() {
//        return new CryptoServiceErrorDecoder();
//    }
//}
//
