package com.idevhub.model;

public class EncryptDTO {

    private String senderCertBase64;
    private String recipientCertBase64;
    private String dataBase64;
    private String recipientSharedKeyBase64;


    public String getSenderCertBase64() {
        return senderCertBase64;
    }

    public void setSenderCertBase64(String senderCertBase64) {
        this.senderCertBase64 = senderCertBase64;
    }

    public String getRecipientCertBase64() {
        return recipientCertBase64;
    }

    public void setRecipientCertBase64(String recipientCertBase64) {
        this.recipientCertBase64 = recipientCertBase64;
    }

    public String getDataBase64() {
        return dataBase64;
    }

    public void setDataBase64(String dataBase64) {
        this.dataBase64 = dataBase64;
    }

    public String getRecipientSharedKeyBase64() {
        return recipientSharedKeyBase64;
    }

    public void setRecipientSharedKeyBase64(String recipientSharedKeyBase64) {
        this.recipientSharedKeyBase64 = recipientSharedKeyBase64;
    }
}
