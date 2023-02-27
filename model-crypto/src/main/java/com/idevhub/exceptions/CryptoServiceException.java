package com.idevhub.exceptions;

import com.idevhub.crypto.service.enums.CryptoServiceError;
import com.idevhub.exceptions.dto.CryptoServiceServiceErrorVM;
import com.netflix.hystrix.exception.ExceptionNotWrappedByHystrix;
import org.springframework.http.HttpStatus;

public class CryptoServiceException extends RuntimeException implements ExceptionNotWrappedByHystrix {
    public final static HttpStatus httpStatus = HttpStatus.SERVICE_UNAVAILABLE;

    private final CryptoServiceError error;

    public CryptoServiceException(CryptoServiceError error, String message) {
        super(message);
        this.error = error;
    }

    public CryptoServiceError getError() {
        return error;
    }

    public CryptoServiceServiceErrorVM createErrorVM() {
        return new CryptoServiceServiceErrorVM(error, getMessage());
    }
}
