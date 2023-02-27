package com.idevhub.crypto.service.enums;

public enum CryptoServiceError {

    Step1Pkcs10Fault,

    Step2Pkcs10Fault,

    MakeHashForSignByPhoneFault,

    MakeDSTU34311DataHashByPhoneFault,

    MakeECDSADataHashByPhoneFault,

    MakeDataHashFault,

    MakeEDSPkcs7EnveloptFault,

    MakeAuthenticHashForMSSP,

    EncryptionVerifyFault,

    MakeDecryptionFault,

    MakeEncryptionFault,

    GetSenderCertFromEnvelopedDataFault,

    MakeAuthenticPksc10hashFault,

    GetSignerinfoFault,

    AuthenticVerifyFault,

    authenticMakePkcs7SignFromRawSign,

    /**
     * No certificate for given crypto service
     */

    CertificateNotFound,
    /**
     * Any internal errors
     */

    GenericError

}
