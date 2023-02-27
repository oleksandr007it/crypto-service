package com.idevhub.model;

public class EncodeKeyDTO {
    private  String senderCertBase64;
    private  String  recipCertBase64;
    private  String  sharedKeyBase64;
    private  String  encryptKeyBase64;


    private  String contentTypeOid;
    private  String  encriptyonAlgorithmOid;
    private  String  dkeBase64;
    private  String  initVectorBase64;

    public EncodeKeyDTO() {
    }

    public EncodeKeyDTO(String senderCertBase64, String recipCertBase64, String sharedKeyBase64, String encryptKeyBase64, String TypeOid, String encriptyonAlgorithmOid, String dkeBase64, String initVectorBase64) {
        this.senderCertBase64 = senderCertBase64;
        this.recipCertBase64 = recipCertBase64;
        this.sharedKeyBase64 = sharedKeyBase64;
        this.encryptKeyBase64 = encryptKeyBase64;
        this.contentTypeOid = TypeOid;
        this.encriptyonAlgorithmOid = encriptyonAlgorithmOid;
        this.dkeBase64 = dkeBase64;
        this.initVectorBase64 = initVectorBase64;
    }

    public String getContentTypeOid() {
        return contentTypeOid;
    }

    public void setContentTypeOid(String contentTypeOid) {
        this.contentTypeOid = contentTypeOid;
    }

    public String getEncriptyonAlgorithmOid() {
        return encriptyonAlgorithmOid;
    }

    public void setEncriptyonAlgorithmOid(String encriptyonAlgorithmOid) {
        this.encriptyonAlgorithmOid = encriptyonAlgorithmOid;
    }

    public String getDkeBase64() {
        return dkeBase64;
    }

    public void setDkeBase64(String dkeBase64) {
        this.dkeBase64 = dkeBase64;
    }

    public String getSenderCertBase64() {
        return senderCertBase64;
    }

    public void setSenderCertBase64(String senderCertBase64) {
        this.senderCertBase64 = senderCertBase64;
    }

    public String getRecipCertBase64() {
        return recipCertBase64;
    }

    public void setRecipCertBase64(String recipCertBase64) {
        this.recipCertBase64 = recipCertBase64;
    }

    public String getSharedKeyBase64() {
        return sharedKeyBase64;
    }

    public void setSharedKeyBase64(String sharedKeyBase64) {
        this.sharedKeyBase64 = sharedKeyBase64;
    }

    public String getEncryptKeyBase64() {
        return encryptKeyBase64;
    }

    public void setEncryptKeyBase64(String encryptKeyBase64) {
        this.encryptKeyBase64 = encryptKeyBase64;
    }

    public String getInitVectorBase64() {
        return initVectorBase64;
    }

    public void setInitVectorBase64(String initVectorBase64) {
        this.initVectorBase64 = initVectorBase64;
    }
}
