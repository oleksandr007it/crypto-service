package com.idevhub.feign;

import com.idevhub.exceptions.CryptoServiceException;
import com.idevhub.model.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

public interface CryptoServiceRemoteAPI {


    /* @ApiOperation(value = "Вычисление хеша из данных для формирования Pksc10.")
     @ApiImplicitParams({
         @ApiImplicitParam(name = "dataBase64", value = "Данные для хеширования в Base64.", required = true, dataType = "string", paramType = "query"),
         @ApiImplicitParam(name = "codeAlgorithm", value = "Выбор алгоритма 0-ДСТУ34311 2-ECDSA", required = true, dataType = "string", paramType = "query")
     })
     @ApiResponses(value = {
         @ApiResponse(code = 200, message = "Возвращает буфер с хешироваными данными в Base64.", response = ResponseEntity.class)})*/
    @PostMapping("/api/authenticp10hash")
    String getAuthenticPksc10hash(@RequestParam("dataBase64") String dataBase64,
                                  @RequestParam("codeAlgorithm") Short codeAlgorithm) throws CryptoServiceException;


    /* @ApiOperation(value = "Вычисление хеша из данных для подписи по телефонному номеру.")
     @ApiImplicitParams({
         @ApiImplicitParam(name = "dataBase64", value = "Данные для хеширования в Base64.", required = true, dataType = "string", paramType = "query"),
         @ApiImplicitParam(name = "acsk", value = "Серийный номер  АЦСК издателя сертификата.", required = true, dataType = "string", paramType = "query"),
         @ApiImplicitParam(name = "serialNumber", value = "Серийный номер сертификата.", required = true, dataType = "string", paramType = "query"),
     })
     @ApiResponses(value = {
         @ApiResponse(code = 200, message = "Возвращает буфер с хешироваными данными в Base64.", response = ResponseEntity.class)})*/
    @PostMapping(value = "/api/authentichash")
    String getAuthenticHashByPhone(
        @RequestParam("dataBase64") String dataBase64,
        @RequestParam("acsk") String acsk,
        @RequestParam("serialNumber") String serialNumber) throws CryptoServiceException;


    /* @ApiOperation(value = "Вычисление хеша из данных для подписи по сертификату.")
     @ApiImplicitParams({
         @ApiImplicitParam(name = "dataBase64", value = "Данные для хеширования в Base64.", required = true, dataType = "string", paramType = "query"),
         @ApiImplicitParam(name = "certBase64", value = "Сертификат  в Base64.", required = true, dataType = "string", paramType = "query"),
      })
     @ApiResponses(value = {
         @ApiResponse(code = 200, message = "Возвращает буфер с хешироваными данными в Base64.", response = ResponseEntity.class)})*/
    @PostMapping(value = "/api/authentichashbycert")
    String getAuthenticHashByCert(
        @RequestParam("dataBase64") String dataBase64,
        @RequestParam("certBase64") String certBase64) throws CryptoServiceException;






  /*  @ApiOperation(value = "Вычисление хеша необходимого для формирования подписи CMS.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "dataHashBase64", value = "Хеш от данных для подписи полученый от /authentichash в Base64.", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "acsk", value = "Серийный номер  АЦСК издателя сертификата.", required = true, dataType = "string", paramType = "query"),
        @ApiImplicitParam(name = "serialNumber", value = "Серийный номер сертификата.", required = true, dataType = "string", paramType = "query"),

    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает буфер с хеш значением в Base64 и хеш с кешом HashToCmsWithCash.", response = PreSignStruct.class)})*/

    @PostMapping("/api/authenticmakehash")
    PreSignStruct getAuthenticMakeHash_ex(
        @RequestParam("dataHashBase64") String dataHashBase64,
        @RequestParam("acsk") String acsk,
        @RequestParam("serialNumber") String serialNumber) throws CryptoServiceException;


    /* @ApiOperation(value = "Возвращает информацию о субъекте из сертификата.")
     @ApiImplicitParams({
         @ApiImplicitParam(name = "certBase64", value = "Бинарное представление сертификата в Base64 ", required = true, dataType = "string", paramType = "query")
     })
     @ApiResponses(value = {
         @ApiResponse(code = 200, message ="" , response = SignerInfo.class)})*/
    @PostMapping("/api/authenticgetsignerinfo")
    SignerInfo authenticGetSignerinfo(@RequestParam("certBase64") String certBase64) throws CryptoServiceException;


    /* @ApiOperation(value = "Формирует подпись CMS в формате Pkcs7.")
     @ApiImplicitParams({
         @ApiImplicitParam(name = "acsk", value = "Серийный номер  АЦСК издателя сертификата.", required = true, dataType = "string", paramType = "query"),
         @ApiImplicitParam(name = "serialNumber", value = "Серийный номер сертификата.", required = true, dataType = "string", paramType = "query"),
         @ApiImplicitParam(name = "dataHashBase64", value = "Хеш от данных для подписи полученый от /authentichash в Base64.", required = true, dataType = "string", paramType = "query"),
         @ApiImplicitParam(name = "hashToCmsWithCash", value = "Хеш с кешем от данных для подписи полученый из  структцуры от /authenticmakehash в Base64.", required = true, dataType = "string", paramType = "query"),
         @ApiImplicitParam(name = "rawSignBase64", value = "raw_sign подпись полученая  от  телефона  в Base64.", required = true, dataType = "string", paramType = "query"),
     })
     @ApiResponses(value = {
         @ApiResponse(code = 200, message = "Возвращает ЕЦП Base64 в формате Pkcs7", response = ResponseEntity.class)})*/
    @PostMapping("/api/authenticmakecmssign2")
    String authenticMakeCmsSign2_ex(@RequestParam("acsk") String acsk,
                                    @RequestParam("serialNumber") String serialNumber,
                                    @RequestParam("dataHashBase64") String dataHashBase64,
                                    @RequestParam("rawSignBase64") String rawSignBase64,
                                    @RequestParam("hashToCmsWithCash") String hashToCmsWithCashBase64) throws CryptoServiceException;


    /*  @ApiOperation(value = "Проверяет внешнюю подпись и возвращает информацию о подписчике.")
      @ApiImplicitParams({
          @ApiImplicitParam(name = "dataBase64", value = "Данные которые подписывались в Base64", required = true, dataType = "string", paramType = "query"),
          @ApiImplicitParam(name = "base64Value", value = "signature буфер c ЭЦП Pkcs7 контейнер в Base64", required = true, dataType = "string", paramType = "query")
      })
      @ApiResponses(value = {
          @ApiResponse(code = 200, message = "Возвращает информацию о подписчике", response = SignerInfo.class)})*/
    @PostMapping(value = "/api/authenticverify")
    SignerInfo getAuthenticVerify(
        @RequestParam("dataBase64") String dataBase64,
        @RequestParam("base64Value") String base64Value) throws CryptoServiceException;

    @PostMapping(value = "/api/verifycert")
    Boolean verifyCert(@RequestParam("certBase64") String certBase64) throws CryptoServiceException;


    /* @ApiOperation(value = "Проверка подписи по хешу.")
     @ApiImplicitParams({
         @ApiImplicitParam(name = "dataHashBase64", value = "hash хеш от данных которые подписывались в Base64", required = true, dataType = "string", paramType = "query"),
         @ApiImplicitParam(name = "signatureBase64", value = "signature буфер c ЭЦП Pkcs7 контейнер в Base64", required = true, dataType = "string", paramType = "query")
     })
     @ApiResponses(value = {
         @ApiResponse(code = 200, message = "Проверка подписи по хешу", response = ResponseEntity.class)})*/
    @PostMapping("/api/authenticverifybyhash")
    void authenticverifybyhash(
        @RequestParam("dataHashBase64") String dataHashBase64,
        @RequestParam("signatureBase64") String signatureBase64) throws CryptoServiceException;


    /*@ApiOperation(value = "Вытаскивает хеш от данных сформированный /authentichash.")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "signatureBase64", value = "signature буфер c ЭЦП Pkcs7 контейнер в Base64", required = true, dataType = "string", paramType = "query")
    })
    @ApiResponses(value = {
        @ApiResponse(code = 200, message = "Возвращает хеш от данных которые подписывались из ЕЦП метод /authentichash", response = ResponseEntity.class)})*/
    @PostMapping("/api/authenticverifyreturnhash")
    String authenticverifyreturnhas(@RequestParam("signatureBase64") String signatureBase64) throws CryptoServiceException;


    /* @ApiOperation(value = "Формирует запрос Pkcs#10 шаг 1")
     @ApiResponses(value = {
         @ApiResponse(code = 200, message = "Возвращается запрос Pkcs#10 на подпись передать на телефон", response = ResponseEntity.class)})*/
    @PostMapping("/api/authenticmakep10step1")
    String authenticmakep10step1(@RequestBody Makep10DTO makep10DTO) throws CryptoServiceException;


    /*  @ApiOperation(value = "Формирует запрос Pkcs#10 шаг 2")
      @ApiResponses(value = {
          @ApiResponse(code = 200, message = "Возвращается запрос Pkcs#10", response = ResponseEntity.class)})*/
    @PostMapping("/api/authenticmakep10step2")
    String authenticmakep10step2(@RequestBody Makep10DTO makep10DTO) throws CryptoServiceException;


    @PostMapping("/api/encrypt/verify")
    String verify(@RequestBody VerifyDTO verifyDTO) throws CryptoServiceException;


    @PostMapping("/api/encrypt/encrypt")
    String encrypt(@RequestBody EncryptDTO encryptDTO) throws CryptoServiceException;


    @PostMapping("/api/encrypt/getcert")
    String getSenderCertFromEnvelopedData(@RequestBody String envelopedDataBase64) throws CryptoServiceException;


    @PostMapping("/api/encrypt/decrypt")
    String newDecrypt(@RequestBody DecryptDTO decryptDTO) throws CryptoServiceException;

    @ResponseBody
    @PostMapping("/api/encrypt/isdynamickeyagreement")
    boolean isDynamicKeyAgreement(@RequestBody String envelopBase64);


    @ResponseBody
    @PostMapping("/api/encrypt/getpublickeyfromcert")
    String getPublicKeyFromCertificate(String recipientCertBase64);

    @ResponseBody
    @PostMapping("/api/encrypt/getpublickeyfromevnelop")
    String getPublicKeyFromEnvelop(@RequestBody String envelopedDataBase64);


    @PostMapping("/api/convertexternaltointernalsign")
    String convertExternalToInternalSign(@RequestBody ExternalToInternalDTO dto) throws CryptoServiceException;


    @PostMapping(value = "/api/authenticverifybydata")
    String getAuthenticVerifyByData(@RequestParam("base64Value") String base64Value) throws CryptoServiceException;

    @PostMapping(value = "/api/internalverifybydata")
    SignerInfo internalVerifyByData(@RequestBody String base64Value) throws CryptoServiceException;


    @PostMapping("/api/digital-signature/get-rnd")
    ResponseEntity<FirstStepDigitalStructureResponse> getRnd() throws Exception;


    @PostMapping("/api/digital-signature/unpack")
    ResponseEntity<SecondStepDigitalStructureResponse> unpack(String sign) throws Exception;

    @PostMapping(value = "/api/makehashforsign")
    String makeHashForSign(@RequestBody MakeHashDTO makeHashDTO) throws CryptoServiceException;

    @PostMapping(value = "/api/verifybydata")
    SignerInfo verifyByData(@RequestBody VerifyByDataDTO dto) throws CryptoServiceException;

    /**
     * \brief  Подпись данных
     * <p>
     * \param[in] key ключ для подписи
     * \param[in] password пароль к ключу
     * \param[in] data данные для подписи
     * \return Возвращает буфер с подписаными данными
     */
    @PostMapping("/api/signbykey")
    String signByKey(@RequestBody SignDTO signDTO) throws CryptoServiceException;


    @PostMapping("/api/encrypt/encryptenvelop")
    String makeEncryptEnvelop(@RequestBody EncryptEnvelopDTO request) throws CryptoServiceException;

    @PostMapping("/api/encrypt/decryptdevelop")
    String makeDecryptDevelop(@RequestBody DecryptDevelopDTO request) throws CryptoServiceException;

    @ResponseBody
    @PostMapping("/api/encrypt/encryptenvelopinternalkey")
    String makeEncryptEnvelopByInternlKey(
        @RequestParam("dataBase64") String dataBase64);


    @ResponseBody
    @PostMapping("/api/encrypt/encodecmskey")
    String makeEncodeForKey(@RequestBody EncodeKeyDTO request);

    @ResponseBody
    @PostMapping("/api/encrypt/decodecmskey")
    String makeDecodeForKey(@RequestBody DecodeKeyDTO request);


}
