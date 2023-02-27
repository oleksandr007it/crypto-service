package com.idevhub.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class SignerInfoDTO {


    @JsonIgnore
    public String signedInfo;
    @JsonIgnore
    byte[] pksc7signature;

    public String subjectKeyIdentifier;
    public String organizationName;
    public String organizationUnitName;
    public String givenName;
    public String surName;
    public String title;
    public String localityName;
    public String commonName;
    public String serialNumber;
    public String okpo;
    public String grfl;
    public String phoneNumber;
    public String subjectNameId;
    private String issuerSerialNumber;
    private String publicKey;
    private String signatureAlgorithm;
    private String expirationTimeNotBefore;
    private String expirationTimeNotAfter;
    private String issuerCommonName;
    private String signatureTimeStamp;
    private String signatureTime;



    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getExpirationTimeNotBefore() {
        return expirationTimeNotBefore;
    }

    public void setExpirationTimeNotBefore(String expirationTimeNotBefore) {
        this.expirationTimeNotBefore = expirationTimeNotBefore;
    }

    public String getExpirationTimeNotAfter() {
        return expirationTimeNotAfter;
    }

    public void setExpirationTimeNotAfter(String expirationTimeNotAfter) {
        this.expirationTimeNotAfter = expirationTimeNotAfter;
    }

    public String getIssuerCommonName() {
        return issuerCommonName;
    }

    public void setIssuerCommonName(String issuerCommonName) {
        this.issuerCommonName = issuerCommonName;
    }

    public String getSignatureTimeStamp() {
        return signatureTimeStamp;
    }

    public void setSignatureTimeStamp(String signatureTimeStamp) {
        this.signatureTimeStamp = signatureTimeStamp;
    }

    public String getSignatureTime() {
        return signatureTime;
    }

    public void setSignatureTime(String signatureTime) {
        this.signatureTime = signatureTime;
    }

    public String getSubjectNameId() {
        return subjectNameId;
    }

    public void setSubjectNameId(String subjectNameId) {
        this.subjectNameId = subjectNameId;
    }

    public String getSignedInfo() {
        return signedInfo;
    }

    public void setSignedInfo(String signedInfo) {
        this.signedInfo = signedInfo;
    }

    public String getIssuerSerialNumber() {
        return issuerSerialNumber;
    }

    public void setIssuerSerialNumber(String issuerSerialNumber) {
        this.issuerSerialNumber = issuerSerialNumber;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getSubjectKeyIdentifier() {
        return subjectKeyIdentifier;
    }

    public void setSubjectKeyIdentifier(String subjectKeyIdentifier) {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
    }

    public byte[] getPksc7signature() {
        return pksc7signature;
    }

    public void setPksc7signature(byte[] pksc7signature) {
        this.pksc7signature = pksc7signature;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public String getOrganizationUnitName() {
        return organizationUnitName;
    }

    public void setOrganizationUnitName(String organizationUnitName) {
        this.organizationUnitName = organizationUnitName;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getSurName() {
        return surName;
    }

    public void setSurName(String surName) {
        this.surName = surName;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getLocalityName() {
        return localityName;
    }

    public void setLocalityName(String localityName) {
        this.localityName = localityName;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getOkpo() {
        return okpo;
    }

    public void setOkpo(String okpo) {
        this.okpo = okpo;
    }

    public String getGrfl() {
        return grfl;
    }

    public void setGrfl(String grfl) {
        this.grfl = grfl;
    }
}
