package com.idevhub.model;

public class SignDTO {


    private String keyBase64;
    private String password;
    private String dataToBeSignBase64;

    public String getKeyBase64() {
        return keyBase64;
    }

    public void setKeyBase64(String keyBase64) {
        this.keyBase64 = keyBase64;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getDataToBeSignBase64() {
        return dataToBeSignBase64;
    }

    public void setDataToBeSignBase64(String dataToBeSignBase64) {
        this.dataToBeSignBase64 = dataToBeSignBase64;
    }
}
