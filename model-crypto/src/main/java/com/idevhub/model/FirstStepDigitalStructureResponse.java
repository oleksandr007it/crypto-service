package com.idevhub.model;

import java.io.Serializable;

public class FirstStepDigitalStructureResponse implements Serializable {
    private  String rnd;
    private  String serverSign;

    public FirstStepDigitalStructureResponse(String rnd, String serverSign) {
        this.rnd = rnd;
        this.serverSign = serverSign;
    }

    public FirstStepDigitalStructureResponse() {
    }

    public void setRnd(String rnd) {
        this.rnd = rnd;
    }

    public String getRnd() {
        return rnd;
    }


    @Override
    public String toString() {
        return "FirstStepDigitalStructureResponse{" +
            "rnd='" + rnd + '\'' +
            ", sign='" + serverSign + '\'' +
            '}';
    }

    public String getServerSign() {
        return serverSign;
    }

    public void setServerSign(String serverSign) {
        this.serverSign = serverSign;
    }
}
