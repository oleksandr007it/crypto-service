package com.idevhub.model;

public class DecryptDevelopDTO {

    private String keyBase64;
    private String keyPassword;
    private String dataToDecrypt;

    public String getKeyBase64() {
        return keyBase64;
    }

    public void setKeyBase64(String keyBase64) {
        this.keyBase64 = keyBase64;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public String getDataToDecrypt() {
        return dataToDecrypt;
    }

    public void setDataToDecrypt(String dataToDecrypt) {
        this.dataToDecrypt = dataToDecrypt;
    }
}
