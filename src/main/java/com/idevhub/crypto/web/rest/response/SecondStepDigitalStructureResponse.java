package com.idevhub.crypto.web.rest.response;


import com.qb.crypto.authentic.SignerInfo;

import java.io.Serializable;

public class SecondStepDigitalStructureResponse extends FirstStepDigitalStructureResponse implements Serializable {

    private final SignerInfo signerInfo;

    public SecondStepDigitalStructureResponse(String rnd, String sign, SignerInfo signerInfo) {
        super(rnd, sign);
        this.signerInfo = signerInfo;
    }

    public SignerInfo getSignerInfo() {
        return signerInfo;
    }
}
