package com.idevhub.exceptions.dto;

import com.idevhub.crypto.service.enums.CryptoServiceError;

public class CryptoServiceServiceErrorVM {
    private CryptoServiceError error;
    private String message;

    public CryptoServiceServiceErrorVM() {
    }

    public CryptoServiceServiceErrorVM (CryptoServiceError error, String message) {
        this.error = error;
        this.message = message;
    }

    public CryptoServiceError  getError() {
        return error;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return "CryptoServiceServiceErrorVM{" +
            "error=" + error +
            ", message='" + message + '\'' +
            '}';
    }
}
