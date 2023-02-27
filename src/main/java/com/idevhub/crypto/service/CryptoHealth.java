package com.idevhub.crypto.service;

import com.qb.crypto.authentic.CryptoException;
import com.qb.crypto.authentic.CryptoHelp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;
import org.springframework.stereotype.Component;

@Component
public class CryptoHealth implements HealthIndicator {

    private final Logger log = LoggerFactory.getLogger(CryptoHealth.class);

    private final CryptoContextHolder cryptoContextHolder;

    public CryptoHealth(CryptoContextHolder cryptoContextHolder) {
        this.cryptoContextHolder = cryptoContextHolder;
    }

    @Override
    public Health health() {
        long cryptoContext = cryptoContextHolder.getContext();
        String testSignatureResult = getTestSignatureResult();
        Health health = createHealthFor(cryptoContext, testSignatureResult);

        return health;
    }

    private String getTestSignatureResult() {
        byte[] dataToBeSigned = "Data to be signed".getBytes();
        boolean isSignatureSuccessful = runTestSignature(dataToBeSigned);
        String signatureResult = isSignatureSuccessful ? "UP" : "DOWN";

        return signatureResult;
    }

    private boolean runTestSignature(byte[] dataToBeSigned) {
        Long lcontext = cryptoContextHolder.getContext();

        byte[] signedData = trySignData(lcontext, dataToBeSigned);
        if (signedData == null) return false;

        byte[] verifiedData = tryVerifyData(lcontext, signedData);

        return verifiedData != null;
    }

    private byte[] trySignData(Long context, byte[] dataToBeSigned) {
        byte[] signedData = null;

        try {
            signedData = CryptoHelp.authentic_sign(context, dataToBeSigned);
        } catch (CryptoException e) {
            log.trace("unable to make authentic signature");
        }

        return signedData;
    }

    private byte[] tryVerifyData(Long context, byte[] dataToBeVerified) {
        byte[] verifiedData = null;

        try {
            verifiedData = CryptoHelp.authentic_verify(context, dataToBeVerified);
        } catch (CryptoException e) {
            log.error("unable to verify authentic signature");
        }

        return verifiedData;
    }

    private Health createHealthFor(long cryptoContext, String testSignatureResult) {
        boolean isOverallHealthStatusOK = getOverallHealthStatusFor(cryptoContext, testSignatureResult);
        Status cryptoSertviceStatus = Status.UP;

        Health health = Health
            .status(cryptoSertviceStatus)
            .withDetail("cryptoContext", cryptoContext)
            .withDetail("sign", testSignatureResult)
            .build();

        return health;
    }

    private boolean getOverallHealthStatusFor(long cryptoContext, String testSignatureResult) {
        boolean isTestSignatureFailed = testSignatureResult.equals("DOWN");
        boolean isCryptoContextNotFound = cryptoContext == 0L;

        if (isTestSignatureFailed || isCryptoContextNotFound) { return false; }

        return true;
    }
}
