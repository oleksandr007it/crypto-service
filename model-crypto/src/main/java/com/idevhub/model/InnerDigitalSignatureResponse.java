package com.idevhub.model;

import java.io.Serializable;

public class InnerDigitalSignatureResponse implements Serializable {
    private  String rnd;
    private  String sign;

    public InnerDigitalSignatureResponse(String rnd, String sign) {
        this.rnd = rnd;
        this.sign = sign;
    }

    public InnerDigitalSignatureResponse() {
    }

    public void setRnd(String rnd) {
        this.rnd = rnd;
    }

    public void setSign(String sign) {
        this.sign = sign;
    }

    public String getRnd() {
        return rnd;
    }

    public String getSign() {
        return sign;
    }

    @Override
    public String toString() {
        return "InnerDigitalSignatureResponse{" +
            "rnd='" + rnd + '\'' +
            ", sign='" + sign + '\'' +
            '}';
    }
}
