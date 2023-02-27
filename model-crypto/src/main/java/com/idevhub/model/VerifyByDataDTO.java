package com.idevhub.model;

import org.springframework.web.bind.annotation.RequestParam;

public class VerifyByDataDTO {
    private  String dataBase64;
    private String base64Value;

    public String getDataBase64() {
        return dataBase64;
    }

    public void setDataBase64(String dataBase64) {
        this.dataBase64 = dataBase64;
    }

    public String getBase64Value() {
        return base64Value;
    }

    public void setBase64Value(String base64Value) {
        this.base64Value = base64Value;
    }

    public VerifyByDataDTO() {
    }

    public VerifyByDataDTO(String dataBase64, String base64Value) {
        this.dataBase64 = dataBase64;
        this.base64Value = base64Value;
    }
}
