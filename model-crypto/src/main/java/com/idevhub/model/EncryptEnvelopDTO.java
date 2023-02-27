package com.idevhub.model;

public class EncryptEnvelopDTO {

    private String keyBase64;
    private String keyPassword;
    private String recipientCertBase64;
    private String dataToEncryptBase64;

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

    public String getRecipientCertBase64() {
        return recipientCertBase64;
    }

    public void setRecipientCertBase64(String recipientCertBase64) {
        this.recipientCertBase64 = recipientCertBase64;
    }

    public String getDataToEncryptBase64() {
        return dataToEncryptBase64;
    }

    public void setDataToEncryptBase64(String dataToEncryptBase64) {
        this.dataToEncryptBase64 = dataToEncryptBase64;
    }
}
