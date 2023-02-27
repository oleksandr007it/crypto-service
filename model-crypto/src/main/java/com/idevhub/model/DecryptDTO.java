package com.idevhub.model;

public class DecryptDTO {


    private String recipientCertBase64;
    private String sharedKeyBase64;
    private String dataBase64;


    public String getRecipientCertBase64() {
        return recipientCertBase64;
    }

    public void setRecipientCertBase64(String recipientCertBase64) {
        this.recipientCertBase64 = recipientCertBase64;
    }

    public String getSharedKeyBase64() {
        return sharedKeyBase64;
    }

    public void setSharedKeyBase64(String sharedKeyBase64) {
        this.sharedKeyBase64 = sharedKeyBase64;
    }

    public String getDataBase64() {
        return dataBase64;
    }

    public void setDataBase64(String dataBase64) {
        this.dataBase64 = dataBase64;
    }
}
