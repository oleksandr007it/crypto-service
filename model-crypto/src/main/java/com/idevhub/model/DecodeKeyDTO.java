package com.idevhub.model;

public class DecodeKeyDTO {
    private  String envelopBase64;
    private  String  sharedKeyBase64;


    public DecodeKeyDTO(String envelopBase64, String sharedKeyBase64) {
        this.envelopBase64 = envelopBase64;
        this.sharedKeyBase64 = sharedKeyBase64;
    }


    public DecodeKeyDTO() {
    }

    public String getEnvelopBase64() {
        return envelopBase64;
    }

    public void setEnvelopBase64(String envelopBase64) {
        this.envelopBase64 = envelopBase64;
    }

    public String getSharedKeyBase64() {
        return sharedKeyBase64;
    }

    public void setSharedKeyBase64(String sharedKeyBase64) {
        this.sharedKeyBase64 = sharedKeyBase64;
    }
}

