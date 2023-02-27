package com.idevhub.crypto.web.rest;

import com.idevhub.crypto.service.CryptoContextHolder;
import com.idevhub.crypto.service.enums.CryptoServiceError;
import com.idevhub.crypto.service.feign.RemoteCertRepo;
import com.idevhub.crypto.web.rest.errors.ActionInvalidSignException;
import com.idevhub.exceptions.CryptoServiceException;
import com.idevhub.model.*;
import com.qb.crypto.authentic.CryptoException;
import com.qb.crypto.authentic.CryptoHelp;
import com.qb.crypto.authentic.SignerInfo;
import feign.FeignException;
import io.swagger.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

@RestController
@RequestMapping("/api")
public class CryptoResource {

    private final String SIGNATURE_ALGORITHM_DSTU = "1.2.804.2.1.1.1.1.3.1.1";
    private final String SIGNATURE_ALGORITHM_ECDSA = "1.2.840.10045.4.1";

    private final RemoteCertRepo remoteCertRepo;
    private final CryptoContextHolder cryptoContextHolder;
    private Long context;

    private int logLevel = 8;

    Logger logger = LoggerFactory.getLogger(getClass());

    public CryptoResource(RemoteCertRepo remoteCertRepo, CryptoContextHolder cryptoContextHolder) {
        this.remoteCertRepo = remoteCertRepo;
        this.cryptoContextHolder = cryptoContextHolder;
        context = cryptoContextHolder.getContext();
        CryptoHelp.set_log_level(context, logLevel);
    }


    @ApiOperation(value = "Вычисление хеша из данных для формирования Pksc10.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "dataBase64", value = "Данные для хеширования в Base64.", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "codeAlgorithm", value = "Выбор алгоритма 0-ДСТУ34311 2-ECDSA", required = true, dataType = "string", paramType = "query")
    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает буфер с хешироваными данными в Base64.", response = ResponseEntity.class)})
    @PostMapping("/authenticp10hash")
    public String getAuthenticPksc10hash(@RequestParam("dataBase64") String dataBase64,
                                         @RequestParam("codeAlgorithm") Short codeAlgorithm) throws CryptoServiceException {
        logger.info("getAuthenticPksc10hash requested, p10={}, algorithm=", dataBase64, codeAlgorithm);
        byte[] dataHash;
        try {
            byte[] data = Base64.getDecoder().decode(dataBase64);
            Long newContext = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(newContext, logLevel);
            setAlgorithmParametrs(newContext, codeAlgorithm);
            dataHash = CryptoHelp.authentic_hash(newContext, null, data);
            CryptoHelp.authentic_free_context(newContext);
        } catch (Exception e) {
            logger.error("getAuthenticPksc10hash failed Exception={}, Message={}", e.getClass().toString(), e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.MakeAuthenticPksc10hashFault, e.getMessage());
        }
        String hashToSend = Base64.getEncoder().encodeToString(dataHash);
        return hashToSend;
    }


    private void setAlgorithmParametrsByCert(Long context, String cert) {
        SignerInfo signerInfo = authenticGetSignerinfo(cert);
        switch (signerInfo.getSignature_algorithm_()) {
            case SIGNATURE_ALGORITHM_DSTU:
                CryptoHelp.authentic_set_param(context, 0, 0);
                break;
            case SIGNATURE_ALGORITHM_ECDSA:
                CryptoHelp.authentic_set_param(context, 0, 1);
                break;
        }

    }

    private void setAlgorithmParametrs(Long context, Short codeAlgorithm) {
        switch (codeAlgorithm) {
            case 0:
                CryptoHelp.authentic_set_param(context, 0, 0);
                break;
            case 2:
                CryptoHelp.authentic_set_param(context, 0, 1);
                break;
        }
    }

    /**
     * POST  /authentichash : Вычисление хеша.
     *
     * @param acsk         Серийный номер  АЦСК издателя сертификата.
     * @param serialNumber Серийный номер сертификата.
     * @param dataBase64   данные для хеширования
     * @return Возвращает буфер с хешироваными данными
     * @throws ActionInvalidSignException 500 (Internal Server Error)
     */
    @ApiOperation(value = "Вычисление хеша из данных для подписи по АЦСК и серийному номеру сертификата.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "dataBase64", value = "Данные для хеширования в Base64.", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "acsk", value = "Серийный номер  АЦСК издателя сертификата.", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "serialNumber", value = "Серийный номер сертификата.", required = true, dataType = "string", paramType = "query")
    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает буфер с хешироваными данными в Base64.", response = ResponseEntity.class)})
    @PostMapping(value = "/authentichash")
    public String getAuthenticHashByPhone(@RequestParam("dataBase64") String dataBase64, @RequestParam("acsk") String acsk,
                                          @RequestParam("serialNumber") String serialNumber) throws CryptoServiceException {

        logger.info("getAuthenticHash by ca and certificate serials, ca={}, cert={}", acsk, serialNumber);
        byte[] cert = getCertByAcskAndSerialNumber(acsk, serialNumber);
        String hashToSend = getAuthenticHash(dataBase64, cert);
        return hashToSend;
    }


    /**
     * POST  /authentichash : Вычисление хеша.
     *
     * @param certBase64 телефонный номер нужен для поиска сертификата
     * @param dataBase64 данные для хеширования
     * @return Возвращает буфер с хешироваными данными
     * @throws ActionInvalidSignException 500 (Internal Server Error)
     */
    @ApiOperation(value = "Вычисление хеша из данных для подписи по сертификату.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "dataBase64", value = "Данные для хеширования в Base64.", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "certBase64", value = "Сертификат  в Base64.", required = true, dataType = "string", paramType = "query")
    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает буфер с хешироваными данными в Base64.", response = ResponseEntity.class)})
    @PostMapping(value = "/authentichashbycert")
    public String getAuthenticHashByCert(@RequestParam("dataBase64") String dataBase64, @RequestParam("certBase64") String certBase64) throws CryptoServiceException {
        logger.info("getAuthenticHashByCert requested, cert={}, data={}", certBase64, dataBase64);
        byte[] cert = Base64.getDecoder().decode(certBase64);
        String hashToSend = getAuthenticHash(dataBase64, cert);
        return hashToSend;
    }


    private String getAuthenticHash(String dataBase64, byte[] cert) {

        byte[] dataHash;
        try {
            Long newContext = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(newContext, logLevel);
            setAlgorithmParametrsByCert(newContext, Base64.getEncoder().encodeToString(cert));
            byte[] data = Base64.getDecoder().decode(dataBase64);
            dataHash = CryptoHelp.authentic_hash(newContext, cert, data);
            CryptoHelp.authentic_free_context(newContext);
        } catch (Exception e) {
            logger.error("getAuthenticHash failed for dataBase64={}, cert={}. Exception={}, Message={}",
                dataBase64, Base64.getEncoder().encodeToString(cert), e.getClass().toString(), e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.MakeDataHashFault, e.getMessage());
        }

        String hashToSend = Base64.getEncoder().encodeToString(dataHash);
        return hashToSend;

    }

    /**
     * POST  /verifycert : Проверка структуры сертификата и цепочки подписей.
     *
     * @param certBase64 файл сертификата в форме Base64
     * @return Возвращает true если сертификат имеет верную структуру и подписи, или false в противном случае
     * @throws CryptoServiceException 503 (Service Unavailable)
     */
    @ApiOperation(value = "Проверка структуры сертификата и цепочки подписей.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "certBase64", value = "Сертификат  в Base64.", required = true, dataType = "string", paramType = "query")
    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает true если сертификат имеет верную структуру и подписи, или false в противном случае", response = ResponseEntity.class)
    })
    @PostMapping(value = "/verifycert")
    public Boolean verifyCert(@RequestParam("certBase64") String certBase64) throws CryptoServiceException {
        logger.info("Certificate verification requested, cert=" + certBase64);
        Long newContext;
        try {
            newContext = CryptoHelp.authentic_clone_context(this.context);
        } catch (CryptoException e) {
            logger.error("verifyCert failed to clone context! Exception={}, Message={}, ErrorCode={}",
                e.getClass().toString(), e.getMessage(), e.getErrorCode());
            throw new CryptoServiceException(CryptoServiceError.GenericError, "Failed to clone context! ErrorCode=" + e.getErrorCode() + " Message=" + e.getMessage());
        }

        CryptoHelp.set_log_level(newContext, logLevel);
        byte[] cert = Base64.getDecoder().decode(certBase64);
        try {
            CryptoHelp.authentic_certificate_verify(newContext, cert);
            return true;
        } catch (CryptoException e) {
            logger.warn("Certificate is not valid. Exception={}, Message={}, ErrorCode={}", e.getClass(), e.getMessage(), e.getErrorCode());
            return false;
        } catch (Exception e) {
            logger.error("Unexpected error occurred while certificate validation", e);
            throw new CryptoServiceException(CryptoServiceError.GenericError, "Unexpected error occurred while certificate validation. "
                + e.getClass() + " Message=" + e.getMessage());
        }
    }


    /**
     * POST  /authenticmakehash : Вычисление хеша необходимого для формирования подписи CMS
     *
     * @param acsk           Серийный номер  АЦСК издателя сертификата.
     * @param serialNumber   Серийный номер сертификата.
     * @param dataHashBase64 хеш от данных для подписи полученый от getAuthenticHashByPhone
     * @return Возвращает буфер хеш значением в Base64
     * @throws Exception 500 (Internal Server Error)
     */
    @ApiOperation(value = "Вычисление хеша необходимого для формирования подписи CMS.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "dataHashBase64", value = "Хеш от данных для подписи полученый от /authentichash в Base64.", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "acsk", value = "Серийный номер  АЦСК издателя сертификата.", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "serialNumber", value = "Серийный номер сертификата.", required = true, dataType = "string", paramType = "query")

    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает буфер с хеш значением в Base64 и хеш с кешом HashToCmsWithCash.", response = PreSignStruct.class)})

    @PostMapping("/authenticmakehash")
    public PreSignStruct getAuthenticMakeHash_ex(@RequestParam("dataHashBase64") String dataHashBase64, @RequestParam("acsk") String acsk,
                                                 @RequestParam("serialNumber") String serialNumber) throws CryptoServiceException {
        logger.info("getAuthenticMakeHash_ex requested, ca={}, cert={}, dataHash={}", acsk, serialNumber, dataHashBase64);

        PreSignStruct preSignStruct = new PreSignStruct();
        try {
            Long newContext = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(newContext, logLevel);
            byte[] cert = getCertByAcskAndSerialNumber(acsk, serialNumber);
            setAlgorithmParametrsByCert(newContext, Base64.getEncoder().encodeToString(cert));
            byte[] dataHash = Base64.getDecoder().decode(dataHashBase64);
            byte[][] hashToCmsBinary = CryptoHelp.authentic_make_hash_ex(newContext, cert, dataHash);
            preSignStruct.setHashToCmsBase64(Base64.getEncoder().encodeToString(hashToCmsBinary[0]));
            preSignStruct.setHashToCmsWithCashBase64(Base64.getEncoder().encodeToString(hashToCmsBinary[1]));
            CryptoHelp.authentic_free_context(newContext);
            logger.debug("serialNumber ={}, authenticmakehash_ex getHashToCmsBase64 = {}", serialNumber, preSignStruct.getHashToCmsBase64());
            logger.debug("serialNumber ={}, authenticmakehash_ex getHashToCmsWithCashBase64 = {}", serialNumber, preSignStruct.getHashToCmsWithCashBase64());
        } catch (Exception e) {
            logger.error("getAuthenticMakeHash_ex failed for dataHash={}, CA={}, Cert={}. Exception={}, Message={}",
                dataHashBase64, acsk, serialNumber, e.getClass().toString(), e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.MakeHashForSignByPhoneFault, e.getMessage());
        }
        return preSignStruct;

    }


    /**
     * * POST /authenticgetsignerinfo : Возвращает информацию о субъекте из сертификата
     *
     * @param certBase64 бинарное представление сертификата
     * @return Информация о субъекте
     * @throws Exception 500 (Internal Server Error)
     */
    @ApiOperation(value = "Возвращает информацию о субъекте из сертификата.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "certBase64", value = "Бинарное представление сертификата в Base64 ", required = true, dataType = "string", paramType = "query")
    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Информация о субъекте", response = SignerInfo.class)})
    @PostMapping("/authenticgetsignerinfo")
    public SignerInfo authenticGetSignerinfo(@RequestParam("certBase64") String certBase64) throws CryptoServiceException {
        logger.info("authenticGetSignerinfo requested, cert={}", certBase64);
        try {
            byte[] cert = Base64.getDecoder().decode(certBase64);
            Long context = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(context, logLevel);
            SignerInfo signerInfo = CryptoHelp.authentic_get_signer_info(context, cert);
            CryptoHelp.authentic_free_context(context);
            return signerInfo;
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.GetSignerinfoFault, e.getMessage());
        }
    }


    /**
     * \brief Формирует подпись CMS
     * <p>
     * \param[in] context крипто-контекст
     * \param[in] certificate сертификат подписанта
     * \param[in] data дпнные для подписи
     * \param[in] raw_sign подпись полученая при помощи authentic_make_raw_sign
     * \return Возвращает ЕЦП в формате Pkcs7
     */

    @ApiOperation(value = "Формирует подпись CMS в формате Pkcs7.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "acsk", value = "Серийный номер  АЦСК издателя сертификата.", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "serialNumber", value = "Серийный номер сертификата.", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "dataHashBase64", value = "Хеш от данных для подписи полученый от /authentichash в Base64.", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "hashToCmsWithCash", value = "Хеш с кешем от данных для подписи полученый из  структцуры от /authenticmakehash в Base64.", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "rawSignBase64", value = "raw_sign подпись полученая  от  телефона  в Base64.", required = true, dataType = "string", paramType = "query"),
    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает ЕЦП Base64 в формате Pkcs7", response = ResponseEntity.class)})
    @PostMapping("/authenticmakecmssign2")
    public String authenticMakeCmsSign2_ex(@RequestParam("acsk") String acsk,
                                           @RequestParam("serialNumber") String serialNumber,
                                           @RequestParam("dataHashBase64") String dataHashBase64,
                                           @RequestParam("rawSignBase64") String rawSignBase64,
                                           @RequestParam("hashToCmsWithCash") String hashToCmsWithCashBase64) throws CryptoServiceException {
        logger.info("Sign as p7s requested, ca={}, cert={}, dataHash={}, rawSign={}, hashToCmsWithCash={}", acsk, serialNumber, dataHashBase64, rawSignBase64, hashToCmsWithCashBase64);
        try {
            byte[] dataHash = Base64.getDecoder().decode(dataHashBase64);
            byte[] rawSign = Base64.getDecoder().decode(rawSignBase64);
            byte[] hashToCmsWithCash = Base64.getDecoder().decode(hashToCmsWithCashBase64);
            byte[] cert = getCertByAcskAndSerialNumber(acsk, serialNumber);

            Long context = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(context, logLevel);
            byte[] cmsSign2 = CryptoHelp.authentic_make_cms_sign2_ex(context, cert, dataHash, rawSign, hashToCmsWithCash);
            CryptoHelp.authentic_free_context(context);
            String cmsSign2Base64 = Base64.getEncoder().encodeToString(cmsSign2);
            return cmsSign2Base64;
        } catch (Exception e) {
            logger.error("authenticMakeCmsSign2_ex failed for CA={}, cert={}, dataHash={}, rawSign={}, hashToCms={}. Exception={}, Message={}",
                acsk, serialNumber, dataHashBase64, rawSignBase64, hashToCmsWithCashBase64, e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.MakeEDSPkcs7EnveloptFault, e.getMessage());
        }

    }


    /**
     * \brief Возвращает информацию о подписчике
     * <p>
     * \param[in] context крипто-контест
     */

    /**
     * \brief Проверка внешней подписи
     * <p>
     * \param[in] context крипто-контест
     * \param[in] signature буфер c ЭЦП
     * \param[in] data данные которые подписывались
     */

    @ApiOperation(value = "Проверяет внешнюю подпись и возвращает информацию о подписчике.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "dataBase64", value = "Данные которые подписывались в Base64", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "base64Value", value = "signature буфер c ЭЦП Pkcs7 контейнер в Base64", required = true, dataType = "string", paramType = "query")
    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает информацию о подписчике", response = SignerInfo.class)})

    @PostMapping(value = "/authenticverify")
    public SignerInfo getAuthenticVerify(@RequestParam("dataBase64") String dataBase64, @RequestParam("base64Value") String base64Value) throws CryptoServiceException {
        logger.info("Verify signature request, data={}, sign={}", dataBase64, base64Value);
        try {
            byte[] pksc7signature = Base64.getDecoder().decode(base64Value);
            byte[] data = Base64.getDecoder().decode(dataBase64);
            Long context = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(context, logLevel);
            CryptoHelp.authentic_verify(context, pksc7signature, data);
            SignerInfo signerInfo = CryptoHelp.authentic_get_token_signer_info(context);
            CryptoHelp.authentic_free_context(context);
            return signerInfo;
        } catch (Exception e) {
            logger.error("Verify signature failed for data={}, sign={}. Exception={}, Message={}", dataBase64, base64Value,
                e.getClass().toString(), e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.AuthenticVerifyFault, e.getMessage());
        }

    }


    @ApiOperation(value = "Проверяет внешнюю подпись и возвращает информацию о подписчике.")
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает информацию о подписчике", response = SignerInfo.class)})

    @PostMapping(value = "/verifybydata")
    public SignerInfo verifyByData(@RequestBody VerifyByDataDTO dto) throws CryptoServiceException {
        logger.info("Verify signature request, data={}, sign={}", dto.getDataBase64(), dto.getBase64Value());
        try {
            byte[] pksc7signature = Base64.getDecoder().decode(dto.getBase64Value());
            byte[] data = Base64.getDecoder().decode(dto.getDataBase64());
            Long context = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(context, logLevel);
            CryptoHelp.authentic_verify(context, pksc7signature, data);
            SignerInfo signerInfo = CryptoHelp.authentic_get_token_signer_info(context);
            CryptoHelp.authentic_free_context(context);
            return signerInfo;
        } catch (Exception e) {
            logger.error("Verify signature failed for data={}, sign={}. Exception={}, Message={}", dto.getDataBase64(), dto.getBase64Value(),
                e.getClass().toString(), e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.AuthenticVerifyFault, e.getMessage());
        }

    }


    /**
     * POST  /authentichash : Вычисление хеша.
     *
     * @param makeHashDTO данные для хеширования
     * @return Возвращает буфер с хешироваными данными
     * @throws ActionInvalidSignException 500 (Internal Server Error)
     */
    @ApiOperation(value = "Вычисление хеша из данных для подписи по АЦСК и серийному номеру сертификата.")
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает буфер с хешироваными данными в Base64.", response = ResponseEntity.class)})
    @PostMapping(value = "/makehashforsign")
    public String makeHashForSign(@RequestBody MakeHashDTO makeHashDTO) throws CryptoServiceException {

        logger.info("getAuthenticHash by ca and certificate serials, ca={}, cert={}", makeHashDTO.getAcsk(), makeHashDTO.getSerialNumber());
        byte[] cert = getCertByAcskAndSerialNumber(makeHashDTO.getAcsk(), makeHashDTO.getSerialNumber());
        String hashToSend = getAuthenticHash(makeHashDTO.getDataBase64(), cert);

        return hashToSend;
    }


    @ApiOperation(value = "Проверяет внутренней  подпись и возвращает информацию о подписчике.")
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает информацию о подписчике.", response = ResponseEntity.class)})

    @PostMapping(value = "/internalverifybydata")
    public SignerInfo internalVerifyByData(@RequestBody String base64Value) throws CryptoServiceException {
        logger.info("Verify signature request, sign={}", base64Value);
        try {

            byte[] pksc7signature = Base64.getDecoder().decode(base64Value);
            Long context = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(context, logLevel);
            byte[] data = CryptoHelp.authentic_verify(context, pksc7signature);
            SignerInfo signerInfo = CryptoHelp.authentic_get_token_signer_info(context);
            CryptoHelp.authentic_free_context(context);
            return signerInfo;
        } catch (Exception e) {
            logger.error("Verify signature failed for  sign={}. Exception={}, Message={}", base64Value,
                e.getClass().toString(), e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.AuthenticVerifyFault, e.getMessage());
        }

    }


    @ApiOperation(value = "Проверяет внутренней  подпись и возвращает данные которые были подписаны.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "base64Value", value = "signature буфер c ЭЦП Pkcs7 и  данные контейнер в Base64", required = true, dataType = "string", paramType = "query")
    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает данные которые были подписаны", response = ResponseEntity.class)})

    @PostMapping(value = "/authenticverifybydata")
    public String getAuthenticVerifyByData(@RequestParam("base64Value") String base64Value) throws CryptoServiceException {
        logger.info("Verify signature request, sign={}", base64Value);
        try {

            byte[] pksc7signature = Base64.getDecoder().decode(base64Value);
            Long context = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(context, logLevel);
            byte[] data = CryptoHelp.authentic_verify(context, pksc7signature);
            CryptoHelp.authentic_free_context(context);
            String dataBase64 = Base64.getEncoder().encodeToString(data);
            return dataBase64;

        } catch (Exception e) {
            logger.error("Verify signature failed for  sign={}. Exception={}, Message={}", base64Value,
                e.getClass().toString(), e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.AuthenticVerifyFault, e.getMessage());
        }

    }


    /**
     * \brief Проверка подписи по хешу
     * <p>
     * \param[in] context крипто-контест
     * \param[in] signature буфер c ЭЦП
     * \param[in] hash хеш от данных которые подписывались
     */
    @ApiOperation(value = "Проверка подписи по хешу.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "dataHashBase64", value = "hash хеш от данных которые подписывались в Base64", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "signatureBase64", value = "signature буфер c ЭЦП Pkcs7 контейнер в Base64", required = true, dataType = "string", paramType = "query")
    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Проверка подписи по хешу", response = ResponseEntity.class)})

    @PostMapping("/authenticverifybyhash")
    public void authenticverifybyhash(@RequestParam("dataHashBase64") String dataHashBase64, @RequestParam("signatureBase64") String signatureBase64) throws CryptoServiceException {
        logger.info("Verify the signature by hash requested, hash={}, sign={}", dataHashBase64, signatureBase64);
        try {
            byte[] signature = Base64.getDecoder().decode(signatureBase64);
            byte[] dataHash = Base64.getDecoder().decode(dataHashBase64);
            Long context = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(context, logLevel);
            CryptoHelp.authentic_verify_by_hash(context, signature, dataHash);
            CryptoHelp.authentic_free_context(context);
        } catch (Exception e) {
            logger.error("Verify the signature by hash failed for hash={}, sign={}. Exception={}, Message={}",
                dataHashBase64, signatureBase64, e.getClass().toString(), e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.AuthenticVerifyFault, e.getMessage());
        }
    }


    /**
     * \brief Вытаскивает хеш от данных
     * \param[in] context крипто-контекст
     * \param[in] signature буфер с ЕЦП
     * \return Возвращает хеш от данных которые подписывались из ЕЦП
     */

    @ApiOperation(value = "Вытаскивает хеш от данных сформированный /authentichash.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "signatureBase64", value = "signature буфер c ЭЦП Pkcs7 контейнер в Base64", required = true, dataType = "string", paramType = "query")
    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает хеш от данных которые подписывались из ЕЦП метод /authentichash", response = ResponseEntity.class)})

    @PostMapping("/authenticverifyreturnhash")
    public String authenticverifyreturnhas(@RequestParam("signatureBase64") String signatureBase64) throws CryptoServiceException {
        logger.info("Extract hash from sign(p7s), sign={}", signatureBase64);
        try {
            byte[] signature = Base64.getDecoder().decode(signatureBase64);
            Long context = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(context, logLevel);
            byte[] dataHash = CryptoHelp.authentic_get_hash_from_sign(context, signature);
            CryptoHelp.authentic_free_context(context);
            String dataHashBase64 = Base64.getEncoder().encodeToString(dataHash);
            return dataHashBase64;
        } catch (Exception e) {
            logger.error("Extract hash from sign(p7s) failed for sign={}. Exception={}, Message={}", signatureBase64, e.getClass(), e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.AuthenticVerifyFault, e.getMessage());
        }
    }


    /**
     * \brief Формирует запрос Pkcs#10
     * <p>
     * <p>
     * MIICFwIBADCBlzEQMA4GA1UECgwHREVGQVVMVDEQMA4GA1UEDAwHREVGQVVMVDEUMBIGA1UEAwwLRW1pbmVtIE9kaW4xDTALBgNVBAQMBE9kaW4xDzANBgNVBCoMBkVtaW5lbTEbMBkGA1UEBRMSVUEtMTIzNDU2Nzg5MC0yMDE3MQswCQYDVQQGEwJVQTERMA8GA1UEBwwI0JrQuNGX0LIwRjAeBgsqhiQCAQEBAQMBATAPBg0qhiQCAQEBAQMBAQIGAyQABCHILXtLlbde7IKMEOSPfYa9h4F/a9eIYSws7+/IwvWCogGgggEuMIIBKgYJKoZIhvcNAQkOMYIBGzCCARcwPQYDVR0JBDYwNDAYBgwqhiQCAQEBCwEEAQExCBMGMTIzNDU2MBgGDCqGJAIBAQELAQQCATEIEwYxMjM0NTYwKQYDVR0OBCIEILtPOen9uG8TdriQqEmeIRfZlJhhOOnFqFgCxlJuYPUjMA4GA1UdDwEB/wQEAwIGwDCBjAYDVR0RBIGEMIGBoB4GDCsGAQQBgZdGAQEEAaAODAwzODA3MzEwMDQwODegMwYMKwYBBAGBl0YBAQQCoCMMIdC/0YDQvtCyLiDQkNGF0YLQuNGA0YHRjNC60LjQuSwgN6AqBgorBgEEAYI3FAIDoBwMGlVQTi0xLjMuNi4xLjQuMS4zMTEuMjAuMi4zMAwGA1UdEwEB/wQCMAA=
     * <p>
     * \param[in] context крипто-контекст
     * \param[in] keyUsage назначение ключа
     * \param[in] publicKey значение публичного ключа
     * \param[in] subjectInfo структура в формате XML
     * \param[in] signature подпись сформированая для запроса методом authentic_make_raw_sign
     * \return Возвращается запрос Pkcs#10
     */
    @ApiOperation(value = "Формирует запрос Pkcs#10 шаг 1")
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращается запрос Pkcs#10 на подпись передать на телефон", response = ResponseEntity.class)})
    @PostMapping("/authenticmakep10step1")
    public String authenticmakep10step1(@RequestBody Makep10DTO makep10DTO) throws CryptoServiceException {
        logger.info("Make p10 (step1) requested, keyUsage={}, publicKey={}", makep10DTO.getKeyUsage(), makep10DTO.getPublicKeyBase64());
        try {
            byte[] publicKey = Base64.getDecoder().decode(makep10DTO.getPublicKeyBase64());
            byte[] subjectInfoFile = Base64.getDecoder().decode(makep10DTO.getSubjectInfoFileBase64());

            Long context = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(context, logLevel);
            byte[] p10 = CryptoHelp.authentic_make_p10(context, makep10DTO.getKeyUsage(), publicKey, subjectInfoFile, null);
            CryptoHelp.authentic_free_context(context);
            String p10Base64 = Base64.getEncoder().encodeToString(p10);
            return p10Base64;
        } catch (Exception e) {
            throw new CryptoServiceException(CryptoServiceError.Step1Pkcs10Fault, e.getMessage());
        }

    }


    @ApiOperation(value = "Формирует запрос Pkcs#10 шаг 2")
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращается запрос Pkcs#10", response = ResponseEntity.class)})
    @PostMapping("/authenticmakep10step2")
    public String authenticmakep10step2(@RequestBody Makep10DTO makep10DTO) throws CryptoServiceException {
        logger.info("Make p10 (step2) requested, keyUsage={}, publicKey={}", makep10DTO.getKeyUsage(), makep10DTO.getPublicKeyBase64());
        try {
            byte[] publicKey = Base64.getDecoder().decode(makep10DTO.getPublicKeyBase64());
            byte[] subjectInfoFile = Base64.getDecoder().decode(makep10DTO.getSubjectInfoFileBase64());
            byte[] signatureForP10 = Base64.getDecoder().decode(makep10DTO.getSignatureForP10Base64());
            Long context = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(context, logLevel);
            byte[] p10 = CryptoHelp.authentic_make_p10(context, makep10DTO.getKeyUsage(), publicKey, subjectInfoFile, signatureForP10);
            CryptoHelp.authentic_free_context(context);
            String p10Base64 = Base64.getEncoder().encodeToString(p10);
            return p10Base64;
        } catch (Exception e) {
            logger.error("Error on make p10 (step2). keyUsage={}, publicKey={}. Exception={}, Message={}",
                makep10DTO.getKeyUsage(), makep10DTO.getPublicKeyBase64(), e.getClass(), e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.Step2Pkcs10Fault, e.getMessage());
        }
    }


    @ApiOperation(value = "Формирует из подписи без данных подпись с данными в нутри")
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает Подпись с данными в нутри", response = ResponseEntity.class)})
    @PostMapping("/convertexternaltointernalsign")
    public String convertExternalToInternalSign(@RequestBody ExternalToInternalDTO dto) throws CryptoServiceException {

        try {
            byte[] externalSign = Base64.getDecoder().decode(dto.getExternalSignBase64());
            byte[] dataSign = Base64.getDecoder().decode(dto.getDataSignBase64());

            Long context = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(context, logLevel);
            byte[] data = CryptoHelp.convert_external_to_internal_sign(externalSign, dataSign);
            CryptoHelp.authentic_free_context(context);
            String dataBase64 = Base64.getEncoder().encodeToString(data);
            return dataBase64;
        } catch (Exception e) {
            logger.error("convertExternalToInternalSign . Exception={}, Message={}", e.getClass(), e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.AuthenticVerifyFault, e.getMessage());
        }
    }


    /**
     * \brief  Подпись данных
     * <p>
     * \param[in] key ключ для подписи
     * \param[in] password пароль к ключу
     * \param[in] data данные для подписи
     * \return Возвращает буфер с подписаными данными
     */

    @ApiOperation(value = "Формирует подпись данных")

    @ApiResponses(value = {
        @ApiResponse(code = 200, message = " Возвращает буфер с подписаными данными", response = ResponseEntity.class)})

    @PostMapping("/signbykey")
    public String signByKey(@RequestBody SignDTO signDTO) throws CryptoServiceException {

        try {
            byte[] key = Base64.getDecoder().decode(signDTO.getKeyBase64());
            byte[] dataToBeSign = Base64.getDecoder().decode(signDTO.getDataToBeSignBase64());

            Long lcontext = CryptoHelp.authentic_clone_context(this.context);
            CryptoHelp.set_log_level(lcontext, logLevel);

            byte[] data = CryptoHelp.authentic_sign_by_key(lcontext, key, signDTO.getPassword(), dataToBeSign);

            CryptoHelp.authentic_free_context(lcontext);
            String dataBase64 = Base64.getEncoder().encodeToString(data);
            return dataBase64;
        } catch (Exception e) {
            logger.error("signByKey   Exception={}, Message={}", e.getClass(), e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.AuthenticVerifyFault, e.getMessage());
        }
    }


    public byte[] getCertByAcskAndSerialNumber(String acsk, String serialNumber) throws CryptoServiceException {

        byte[] cert;
        try {
            cert = remoteCertRepo.getCertStorageByAcskAndSerialNumber(acsk, serialNumber);
        } catch (FeignException e) {
            if (e.status() == 404)
                logger.error(e.getMessage());
            throw new CryptoServiceException(CryptoServiceError.CertificateNotFound, e.getMessage());
        }
        return cert;
    }

}






