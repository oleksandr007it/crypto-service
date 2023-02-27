package com.idevhub.model;


import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

@ApiModel(value = "Makep10DTO", description = "")
public class Makep10DTO {

    @ApiModelProperty(value = "Назначение ключа")
    private int keyUsage;
    @ApiModelProperty(value = "значение публичного ключа в Base64")
    private String publicKeyBase64;
    @ApiModelProperty(value = "структура в формате XML в Base64")
    private String subjectInfoFileBase64;
    @ApiModelProperty(value = "signature подпись сформированая на телефоне")
    private String signatureForP10Base64;


    public int getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(int keyUsage) {
        this.keyUsage = keyUsage;
    }

    public String getPublicKeyBase64() {
        return publicKeyBase64;
    }

    public void setPublicKeyBase64(String publicKeyBase64) {
        this.publicKeyBase64 = publicKeyBase64;
    }

    public String getSubjectInfoFileBase64() {
        return subjectInfoFileBase64;
    }

    public void setSubjectInfoFileBase64(String subjectInfoFileBase64) {
        this.subjectInfoFileBase64 = subjectInfoFileBase64;
    }

    public String getSignatureForP10Base64() {
        return signatureForP10Base64;
    }

    public void setSignatureForP10Base64(String signatureForP10Base64) {
        this.signatureForP10Base64 = signatureForP10Base64;
    }
}
