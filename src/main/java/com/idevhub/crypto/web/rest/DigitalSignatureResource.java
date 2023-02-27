package com.idevhub.crypto.web.rest;

import com.idevhub.crypto.service.CertProvImpl;
import com.idevhub.crypto.service.CryptoContextHolder;
import com.idevhub.crypto.service.feign.RemoteCertRepo;
import com.idevhub.crypto.web.rest.errors.InternalServerErrorException;
import com.idevhub.crypto.web.rest.response.FirstStepDigitalStructureResponse;
import com.idevhub.crypto.web.rest.response.SecondStepDigitalStructureResponse;
import com.idevhub.protocol.platform.service.PlatformLogger;
import com.qb.crypto.authentic.CryptoHelp;
import com.qb.crypto.authentic.SignerInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Random;

@RestController
@RequestMapping("/api/digital-signature")
public class DigitalSignatureResource {

    Logger log = LoggerFactory.getLogger(DigitalSignatureResource.class);
    private final PlatformLogger logger = PlatformLogger.getInstance();
    @Autowired
    private ThreadLocal<PlatformLogger.Meta> metaThreadLocal;

    private final RemoteCertRepo remoteCertRepo;
    private final CertProvImpl certProv;
    private final CryptoContextHolder cryptoContextHolder;
    private Long context;
    private int logLevel=8;


    public DigitalSignatureResource(RemoteCertRepo remoteCertRepo,
                                    CertProvImpl certProv,
                                    CryptoContextHolder cryptoContextHolder) {
        this.remoteCertRepo = remoteCertRepo;
        this.certProv = certProv;
        this.cryptoContextHolder = cryptoContextHolder;
        context = cryptoContextHolder.getContext();
        CryptoHelp.set_log_level(context, logLevel);
    }


    @PostMapping("/get-rnd")
    public ResponseEntity<FirstStepDigitalStructureResponse> getRnd() throws Exception {
        log.debug("Rest call to get RND. Trying to clone context");
        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong())));
        logger.meta(metaThreadLocal.get())
            .debug("Rest call to get RND. Trying to clone context");

//        context = cryptoContextHolder.getContext();
//        CryptoHelp.set_log_level(context, logLevel);

        Long context = CryptoHelp.authentic_clone_context(this.context);
//        CryptoHelp.set_log_level(context, logLevel);
        log.debug("Context is ready.");
        logger.meta(metaThreadLocal.get())
            .trace("Context is ready.");
        byte[] rnd = CryptoHelp.authentic_gen_rnd();
        log.debug("Got RND");
        logger.meta(metaThreadLocal.get())
            .trace("Got RND : {}", rnd);

        byte[] sign = CryptoHelp.authentic_sign(context, rnd);
        log.debug("GOT sign");
        logger.meta(metaThreadLocal.get())
            .trace("GOT sign : {}", sign);
        CryptoHelp.authentic_free_context(context);

        String stringRND = Base64.getEncoder().encodeToString(rnd);
        String stringSign = Base64.getEncoder().encodeToString(sign);

        if (stringRND == null || stringSign == null) {
            logger.meta(metaThreadLocal.get())
                .warn("nullable answer from CryptoLibrary");
            throw new InternalServerErrorException("nullable answer from CryptoLibrary");
        }
        return ResponseEntity.ok(
            new FirstStepDigitalStructureResponse(
                stringRND,
                stringSign
            )
        );
    }

    @PostMapping("/unpack")
    public ResponseEntity<SecondStepDigitalStructureResponse> unpack(String sign) throws Exception {

        metaThreadLocal.set(logger.newMeta()
            .pid(Math.abs(new Random().nextLong()))
            .ppid(String.valueOf(Math.abs(sign.hashCode()))));
        logger.meta(metaThreadLocal.get())
            .debug("Rest to unpack. sign : {}", sign);

        Long context = CryptoHelp.authentic_clone_context(this.context);
        CryptoHelp.set_log_level(context, logLevel);
        byte[] serverSign = Base64.getDecoder().decode(sign);
        byte[] rnd = CryptoHelp.authentic_verify(context, serverSign);
        logger.meta(metaThreadLocal.get())
            .trace("Got serverSign {} and rnd {}", sign, rnd);
        SignerInfo signerInfo = CryptoHelp.authentic_get_token_signer_info(context);

        CryptoHelp.authentic_free_context(context);

        String encodedRnd = Base64.getEncoder().encodeToString(rnd);
        String encodedServerSign = Base64.getEncoder().encodeToString(serverSign);


        if (encodedRnd == null || encodedServerSign == null || signerInfo == null) {
            logger.meta(metaThreadLocal.get())
                .warn("nullable answer from CryptoLibrary, cannot continue");
            throw new InternalServerErrorException("nullable answer from CryptoLibrary, cannot continue");
        }


        return ResponseEntity.ok(
            new SecondStepDigitalStructureResponse(
                encodedRnd,
                encodedServerSign,
                signerInfo
            )
        );
    }

}
