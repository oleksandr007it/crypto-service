package com.idevhub.model;

public class VerifyDTO {
    private String senderCertBase64;
    private boolean senderOscp;
    private boolean senderCrl;
    private String recipientCertBase64;
    private boolean recipientOscp;
    private boolean recipientCrl;


    public String getSenderCertBase64() {
        return senderCertBase64;
    }

    public void setSenderCertBase64(String senderCertBase64) {
        this.senderCertBase64 = senderCertBase64;
    }

    public boolean isSenderOscp() {
        return senderOscp;
    }

    public void setSenderOscp(boolean senderOscp) {
        this.senderOscp = senderOscp;
    }

    public boolean isSenderCrl() {
        return senderCrl;
    }

    public void setSenderCrl(boolean senderCrl) {
        this.senderCrl = senderCrl;
    }

    public String getRecipientCertBase64() {
        return recipientCertBase64;
    }

    public void setRecipientCertBase64(String recipientCertBase64) {
        this.recipientCertBase64 = recipientCertBase64;
    }

    public boolean isRecipientOscp() {
        return recipientOscp;
    }

    public void setRecipientOscp(boolean recipientOscp) {
        this.recipientOscp = recipientOscp;
    }

    public boolean isRecipientCrl() {
        return recipientCrl;
    }

    public void setRecipientCrl(boolean recipientCrl) {
        this.recipientCrl = recipientCrl;
    }
}
