package com.idevhub.model;




import java.io.Serializable;

public class SecondStepDigitalStructureResponse extends FirstStepDigitalStructureResponse implements Serializable {

    private SignerInfo signerInfo;

    public SecondStepDigitalStructureResponse() {
    }

    public SecondStepDigitalStructureResponse(String rnd, String sign, SignerInfo signerInfo) {
        super(rnd, sign);
        this.signerInfo = signerInfo;
    }

    public void setSignerInfo(SignerInfo signerInfo) {
        this.signerInfo = signerInfo;
    }

    public SignerInfo getSignerInfo() {
        return signerInfo;
    }
}
