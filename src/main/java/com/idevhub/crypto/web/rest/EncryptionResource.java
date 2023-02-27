package com.idevhub.crypto.web.rest;

import com.idevhub.crypto.service.CertProvImpl;
import com.idevhub.crypto.service.CryptoContextHolder;
import com.idevhub.crypto.service.enums.CryptoServiceError;
import com.idevhub.crypto.service.feign.RemoteCertRepo;
import com.idevhub.exceptions.CryptoServiceException;
import com.idevhub.model.*;
import com.idevhub.protocol.platform.service.PlatformLogger;
import com.qb.crypto.authentic.CryptoException;
import com.qb.crypto.authentic.CryptoHelp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Hashtable;
import java.util.Random;

import static com.idevhub.crypto.web.rest.util.CryptographyLibraryUtil.getPublicKeyByCertificate;

@SuppressWarnings("Duplicates")
@RestController
@RequestMapping("/api/encrypt")
public class EncryptionResource {

    Logger log = LoggerFactory.getLogger(EncryptionResource.class);
    private final PlatformLogger logger = PlatformLogger.getInstance();
    @Autowired
    private ThreadLocal<PlatformLogger.Meta> metaThreadLocal;

    private final RemoteCertRepo remoteCertRepo;
    private final CertProvImpl certProv;

    private final CryptoContextHolder cryptoContextHolder;
    private Long context;

    public EncryptionResource(RemoteCertRepo remoteCertRepo, CertProvImpl certProv, CryptoContextHolder cryptoContextHolder) {
        this.remoteCertRepo = remoteCertRepo;
        this.certProv = certProv;

        this.cryptoContextHolder = cryptoContextHolder;
        context = cryptoContextHolder.getContext();
    }

    @ResponseBody
    @PostMapping("/verify")
    public String verify(@RequestBody VerifyDTO verifyDTO) throws CryptoServiceException {
        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong()))
            .ppid(String.valueOf(Math.abs(verifyDTO.getSenderCertBase64().hashCode()))));
        logger.meta(metaThreadLocal.get())
            .debug("Verifying verifyDTO : {}", verifyDTO);

        try {
            Long context = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(context, 3);


            byte[] senderCert = Base64.getDecoder().decode(verifyDTO.getSenderCertBase64());
            byte[] recipientCert = Base64.getDecoder().decode(verifyDTO.getRecipientCertBase64());

            boolean resultOfComparing = CryptoHelp.authentic_compare_certificate_params(context, senderCert, recipientCert);


            //if verify ok - return public key of recipient
            byte[] recipientPublicKey = (resultOfComparing) ? getPublicKeyByCertificate(context, recipientCert) : new byte[]{};


            CryptoHelp.authentic_free_context(context);

            String recipientPublicKeyBase64 = Base64.getEncoder().encodeToString(recipientPublicKey);
            return recipientPublicKeyBase64;

        } catch (CryptoException e) {
            logger.meta(metaThreadLocal.get())
                .warn("Exception during Verifying verifyDTO. e : {}", e.getLocalizedMessage());
            log.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.EncryptionVerifyFault, e.getMessage());
        }
    }


    @ResponseBody
    @PostMapping("/encrypt")
    public String encrypt(@RequestBody EncryptDTO encryptDTO) throws CryptoServiceException {
        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong()))
            .ppid(String.valueOf(Math.abs(encryptDTO.getSenderCertBase64().hashCode()))));
        logger.meta(metaThreadLocal.get())
            .debug("Encrypting encryptDTO : {}", encryptDTO);

        try {
            Long context = CryptoHelp.authentic_clone_context(this.context);

            byte[] recipientCert = Base64.getDecoder().decode(encryptDTO.getRecipientCertBase64());
            byte[] senderCert = Base64.getDecoder().decode(encryptDTO.getSenderCertBase64());


            byte[] recipientPublicKey = getPublicKeyByCertificate(context, recipientCert);
            byte[] senderPublicKey = getPublicKeyByCertificate(context, senderCert);
            byte[] data = Base64.getDecoder().decode(encryptDTO.getDataBase64());


            Hashtable<byte[], byte[]> hashtable;
            if (CryptoHelp.authentic_compare_certificate_params(context, recipientCert, senderCert)) {
                byte[] sharedKey = Base64.getDecoder().decode(encryptDTO.getRecipientSharedKeyBase64());
                hashtable = new Hashtable<>();
                hashtable.put(recipientPublicKey, sharedKey);
            } else {
                byte[] dynamyc_shared = CryptoHelp.authentic_gen_shared_key(context, recipientCert);
                hashtable = new Hashtable<>();
                hashtable.put(recipientPublicKey, dynamyc_shared);
            }

            byte[] encryptedData = CryptoHelp.authentic_envelop_make2(context, senderPublicKey, hashtable, data);
            CryptoHelp.authentic_free_context(context);


            String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedData);
            return encryptedDataBase64;
        } catch (CryptoException e) {
            logger.meta(metaThreadLocal.get())
                .warn("Exception during Encrypting encryptDTO. e : {}", e.getLocalizedMessage());
            log.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.MakeEncryptionFault, e.getMessage());
        }
    }

    @ResponseBody
    @PostMapping("/getcert")
    public String getSenderCertFromEnvelopedData(@RequestBody String envelopedDataBase64) throws CryptoServiceException {
        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong()))
            .ppid(String.valueOf(Math.abs(envelopedDataBase64.hashCode()))));
        logger.meta(metaThreadLocal.get())
            .debug("Getting Sender Cert From Enveloped Data where envelopedDataBase64 : {}", envelopedDataBase64);

        try {
            Long context = CryptoHelp.authentic_clone_context(this.context);
            byte[] enveloped_data = Base64.getDecoder().decode(envelopedDataBase64);
            byte[] senderCert = CryptoHelp.authentic_get_sender_cert_from_enveloped_data(context, enveloped_data);
            String senderCertBase64 = Base64.getEncoder().encodeToString(senderCert);
            return senderCertBase64;
        } catch (CryptoException e) {
            logger.meta(metaThreadLocal.get())
                .warn("Exception during Getting Sender Cert From Enveloped Data. e : {}", e.getLocalizedMessage());
            log.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.GetSenderCertFromEnvelopedDataFault, e.getMessage());
        }
    }

    @ResponseBody
    @PostMapping("/getpublickeyfromcert")
    public String getPublicKeyFromCertificate(String recipientCertBase64) {
        try {

            Long lcontext = CryptoHelp.authentic_clone_context(this.context);
            byte[] recipientCert = Base64.getDecoder().decode(recipientCertBase64);
            byte[] pkey = getPublicKeyByCertificate(lcontext, recipientCert);
            String pkeyBase64 = Base64.getEncoder().encodeToString(pkey);
            CryptoHelp.authentic_free_context(lcontext);
            return pkeyBase64;

        } catch (CryptoException e) {
            logger.meta(metaThreadLocal.get())
                .warn("Exception during Getting getpublickeyfromcert e : {}", e.getLocalizedMessage());
            log.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.GetSenderCertFromEnvelopedDataFault, e.getMessage());
        }

    }


    @ResponseBody
    @PostMapping("/getpublickeyfromevnelop")
    public String getPublicKeyFromEnvelop(@RequestBody String envelopedDataBase64) {
        try {
            String result = getSenderCertFromEnvelopedData(envelopedDataBase64);

            return result;
        } catch (Exception e) {
            logger.meta(metaThreadLocal.get())
                .warn("Exception during Getting public key From Enveloped Data. e : {}", e.getLocalizedMessage());
            log.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.GetSenderCertFromEnvelopedDataFault, e.getMessage());
        }
    }


    @ResponseBody
    @PostMapping("/decrypt")
    public String newDecrypt(@RequestBody DecryptDTO decryptDTO) throws CryptoServiceException {
        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong()))
            .ppid(String.valueOf(Math.abs(decryptDTO.getDataBase64().hashCode()))));
        logger.meta(metaThreadLocal.get())
            .debug("Rest to newDecrypt with decryptDTO : {}", decryptDTO);

        try {
            Long lcontext = CryptoHelp.authentic_clone_context(this.context);


            byte[] sharedKey = Base64.getDecoder().decode(decryptDTO.getSharedKeyBase64());
            byte[] data = Base64.getDecoder().decode(decryptDTO.getDataBase64());
            byte[] recipientCert = Base64.getDecoder().decode(decryptDTO.getRecipientCertBase64());


            byte[] recipientPublicKey = getPublicKeyByCertificate(lcontext, recipientCert);

            byte[] decryptedData = CryptoHelp.authentic_develop2(lcontext, recipientPublicKey, sharedKey, data);
            CryptoHelp.authentic_free_context(lcontext);
            String decryptedDataBase64 = Base64.getEncoder().encodeToString(decryptedData);
            return decryptedDataBase64;
        } catch (CryptoException e) {
            log.error(e.getMessage());
            logger.meta(metaThreadLocal.get())
                .warn("Exception during Rest to newDecrypt. e : {}", e.getLocalizedMessage());
            throw new CryptoServiceException(CryptoServiceError.MakeDecryptionFault, e.getMessage());
        }
    }


    /**
     * \brief Выполняет шифрование данных и заворачивает в конверт CMS
     * \param[in] context крипто-контекст
     * \param[in] key ключ на котором выполняется шифрование
     * \param[in] pass пароль к ключу
     * \param[in] recipient_cert сертификат получателя
     * \param[in] data данные для шифрования
     * \return Шифрованый конверт
     */
    @ResponseBody
    @PostMapping("/encryptenvelop")
    public String makeEncryptEnvelop(@RequestBody EncryptEnvelopDTO request) throws CryptoServiceException {
        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong()))
            .ppid(String.valueOf(Math.abs(request.getDataToEncryptBase64().hashCode()))));
        logger.meta(metaThreadLocal.get())
            .debug("Making encrypt envelop by EncryptEnvelopDTO : {}", request);
        try {
            Long lcontext = CryptoHelp.authentic_clone_context(this.context);
            byte[] key = Base64.getDecoder().decode(request.getKeyBase64());
            byte[] recipienCert = Base64.getDecoder().decode(request.getRecipientCertBase64());
            byte[] data = Base64.getDecoder().decode(request.getDataToEncryptBase64());

            byte[] encryptedData = CryptoHelp.authentic_envelop(lcontext, key, request.getKeyPassword(), recipienCert, data);

            CryptoHelp.authentic_free_context(lcontext);
            String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedData);
            return encryptedDataBase64;
        } catch (CryptoException e) {
            logger.meta(metaThreadLocal.get())
                .warn("Exception during Making encrypt envelop. e : {}", e.getLocalizedMessage());
            log.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.MakeEncryptionFault, e.getMessage());
        }
    }

    @ResponseBody
    @PostMapping("/decryptdevelop")
    public String makeDecryptDevelop(@RequestBody DecryptDevelopDTO request) throws CryptoServiceException {

        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong()))
            .ppid(String.valueOf(Math.abs(request.getDataToDecrypt().hashCode()))));
        logger.meta(metaThreadLocal.get())
            .debug("Making decrypt develop by DecryptDevelopDTO : {}", request);

        try {
            Long lcontext = CryptoHelp.authentic_clone_context(this.context);
            byte[] key = Base64.getDecoder().decode(request.getKeyBase64());
            byte[] data = Base64.getDecoder().decode(request.getDataToDecrypt());

            byte[] decrypted = CryptoHelp.authentic_develop(lcontext, key, request.getKeyPassword(), data);

            CryptoHelp.authentic_free_context(lcontext);
            String encryptedDataBase64 = Base64.getEncoder().encodeToString(decrypted);
            return encryptedDataBase64;
        } catch (CryptoException e) {
            logger.meta(metaThreadLocal.get())
                .warn("Exception during Making decrypt develop. e : {}", e.getLocalizedMessage());
            log.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.MakeEncryptionFault, e.getMessage());
        }
    }


    /**
     * \brief Выполняет шифрование данных и заворачивает в конверт CMS
     * Ключ на котором выполняется шифрование берется из настроек контекста из следующего блока
     * \code
     * ...
     * <PrivateKey>
     * <SubjectIdentifier>63DDF528C354B153C85339491E59BC7C8122600527DBE1CA7368CA373BDBEDD5</SubjectIdentifier>
     * <KeyUsage>08</KeyUsage>
     * ...
     * </PrivateKey>
     * ...
     * \endcode
     * а сертификат получателя определяется по идентификатору ключа указоному в контексте, сертификат должен присутствовать в хранилище
     * \code
     * ...
     * <RecipientsInfo>
     * <KAUserCertificate publicKey="4C32C1764E815F8370A5FD20AA00CA95B46542E1F93A28EB99879AED35CF8F15" algorithm="1.2.804.2.1.1.1.1.3.1.1"/>
     * </RecipientsInfo>
     * ...
     * \endcode
     * \param[in] context крипто-контекст
     * \param[in] data данные для шифрования
     * \return Шифрованый конверт
     */
    @ResponseBody
    @PostMapping("/encryptenvelopinternalkey")
    public String makeEncryptEnvelopByInternlKey(
        @RequestParam("dataBase64") String dataBase64) {
        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong()))
            .ppid(String.valueOf(Math.abs(dataBase64.hashCode()))));
        logger.meta(metaThreadLocal.get())
            .debug("Making encrypt envelop by internal key. dataBase64 : {}", dataBase64);

        try {
            Long lcontext = CryptoHelp.authentic_clone_context(this.context);
            byte[] data = Base64.getDecoder().decode(dataBase64);
            byte[] encryptedData = CryptoHelp.authentic_envelop(lcontext, data);
            CryptoHelp.authentic_free_context(lcontext);
            String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedData);
            return encryptedDataBase64;
        } catch (CryptoException e) {
            logger.meta(metaThreadLocal.get())
                .warn("Exception during Making encrypt envelop by internal key. e : {}", e.getLocalizedMessage());
            log.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.MakeEncryptionFault, e.getMessage());
        }
    }

    @ResponseBody
    @PostMapping("/decryptdevelopinternalkey")
    public String makeDecryptEnvelopByInternlKey(
        @RequestParam("dataBase64") String dataBase64) {
        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong()))
            .ppid(String.valueOf(Math.abs(dataBase64.hashCode()))));
        logger.meta(metaThreadLocal.get())
            .debug("Making decrypt envelop by internal key. dataBase64 : {}", dataBase64);
        try {
            Long lcontext = CryptoHelp.authentic_clone_context(this.context);
            byte[] data = Base64.getDecoder().decode(dataBase64);
            byte[] encryptedData = CryptoHelp.authentic_develop(lcontext, data);
            CryptoHelp.authentic_free_context(lcontext);
            String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedData);
            return encryptedDataBase64;
        } catch (CryptoException e) {
            logger.meta(metaThreadLocal.get())
                .warn("Exception during Making decrypt envelop by internal key. e : {}", e.getLocalizedMessage());
            log.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.MakeDecryptionFault, e.getMessage());
        }
    }

    /**
     * \brief Выполняет формирование CMS конверта без шифрованых данных
     * <p>
     * \param[in] context крипто-контекст
     * \param[in] sender_cert сертификат отправителя
     * \param[in] recip_cert сертификат получателя
     * \param[in] shared_key общий секрет
     * \param[in] encrypt_key ключ на котором шифруются данные КШД
     * \param[in] content_type_oid определяет тип зашифрованны данных
     * \param[in] encriptyon_algorithm_oid определяет алгоритм щифрования приминенный при шифровании данных
     * \param[in] iv вектор инициализации приминенный при шифровании данных.
     * Опциональный если указан как null будет закодирован нулевой вектор
     * \param[in] dke ДКЕ приминенный при шифровании данных. Опциональный если null будет закодирован ДКЕ№1
     * \return Шифрованый конверт CMS без данных
     */

    @ResponseBody
    @PostMapping("/encodecmskey")
    public String makeEncodeForKey(
        @RequestBody EncodeKeyDTO request) {
        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong()))
            .ppid(String.valueOf(Math.abs(request.getEncryptKeyBase64().hashCode()))));
        logger.meta(metaThreadLocal.get())
            .debug("Making CMS envelope without encrypted data : {}", request);
        try {
            Long lcontext = CryptoHelp.authentic_clone_context(this.context);
            byte[] senderCert = Base64.getDecoder().decode(request.getSenderCertBase64());
            byte[] recipCert = Base64.getDecoder().decode(request.getRecipCertBase64());
            byte[] sharedKey = null;
            byte[] encryptKey = Base64.getDecoder().decode(request.getEncryptKeyBase64());
            byte[] initVector = null;
            if (request.getInitVectorBase64() != null) {
                initVector = Base64.getDecoder().decode(request.getInitVectorBase64());
            }
            byte[] dke = null;
            if (request.getDkeBase64() != null) {
                dke = Base64.getDecoder().decode(request.getDkeBase64());
            }


            String сontentTypeOid = request.getContentTypeOid();
            String encriptyonAlgorithmOid = request.getEncriptyonAlgorithmOid();

            if (CryptoHelp.authentic_compare_certificate_params(lcontext, senderCert, recipCert)) {
                sharedKey = Base64.getDecoder().decode(request.getSharedKeyBase64());
            } else {
                sharedKey = CryptoHelp.authentic_gen_shared_key(lcontext, recipCert);
            }


            byte[] encryptedData = CryptoHelp.authentic_encode_cms(lcontext, senderCert, recipCert, sharedKey, encryptKey, сontentTypeOid, encriptyonAlgorithmOid, initVector, dke);

            CryptoHelp.authentic_free_context(lcontext);
            String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedData);
            return encryptedDataBase64;
        } catch (CryptoException e) {
            logger.meta(metaThreadLocal.get())
                .warn("Exception during Making CMS envelope without encrypted data. e : {}", e.getLocalizedMessage());
            log.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.MakeEncryptionFault, e.getMessage());
        }
    }


    /**
     * \brief Дэкодирует CMS конверт и извликает вектор инициализации и КШД
     * <p>
     * \param[in] context крипто-контекст
     * \param[in] envelop конверт CMS
     * \param[in] shared_key общий секрет
     * \return ключ КШД
     */

    @ResponseBody
    @PostMapping("/decodecmskey")
    public String makeDecodeForKey(
        @RequestBody DecodeKeyDTO request) {
        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong()))
            .ppid(String.valueOf(Math.abs(request.getSharedKeyBase64().hashCode()))));
        logger.meta(metaThreadLocal.get())
            .debug("Making Decodes a CMS envelope and retrieves the initialization vector and KEY : {}", request);
        try {
            Long lcontext = CryptoHelp.authentic_clone_context(this.context);
            byte[] envelop = Base64.getDecoder().decode(request.getEnvelopBase64());
            byte[] sharedKey = Base64.getDecoder().decode(request.getSharedKeyBase64());

            byte[] encryptedData = CryptoHelp.authentic_decode_cms(lcontext, envelop, sharedKey);
            CryptoHelp.authentic_free_context(lcontext);
            String decodeKeyResponse = Base64.getEncoder().encodeToString(encryptedData);
            return decodeKeyResponse;

        } catch (CryptoException e) {
            logger.meta(metaThreadLocal.get())
                .warn("Exception during Making Making Decodes a CMS envelope and retrieves the initialization vector and KEY. e : {}", e.getLocalizedMessage());
            log.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.MakeDecryptionFault, e.getMessage());
        }
    }


    /**
     * \brief Определяет какая схема согласования ключей была применена
     * при формировании шифрованного конверта
     * \param[in] envelop шифрованый конверт СМС
     * \return возвращает true, если динамическая и false, если статическая схема шифрования
     */

    @ResponseBody
    @PostMapping("/isdynamickeyagreement")
    public boolean isDynamicKeyAgreement(@RequestBody String envelopBase64) {

        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong()))
            .ppid(String.valueOf(Math.abs(envelopBase64.hashCode()))));
        logger.meta(metaThreadLocal.get())
            .debug("Making isDynamicKeyAgreement : {}", envelopBase64);
        try {
            Long lcontext = CryptoHelp.authentic_clone_context(this.context);
            byte[] envelop = Base64.getDecoder().decode(envelopBase64);
            boolean result = CryptoHelp.authentic_is_dynmic_key_agreement(envelop);
            CryptoHelp.authentic_free_context(lcontext);
            return result;
        } catch (Exception e) {
            logger.meta(metaThreadLocal.get())
                .warn("Exception during isDynamicKeyAgreement  e : {}", e.getLocalizedMessage());
            log.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.GenericError, e.getMessage());
        }

    }


}
