package com.idevhub.crypto.web.rest.errors;


import com.netflix.hystrix.exception.ExceptionNotWrappedByHystrix;

public class ActionInvalidSignException extends CustomParameterizedException implements ExceptionNotWrappedByHystrix {
    public ActionInvalidSignException(String message, String... params) {
        super(message, params);
    }

}
