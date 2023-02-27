package com.idevhub.crypto.service;

import com.google.common.base.Strings;
import com.idevhub.protocol.platform.service.PlatformLogger;
import com.qb.crypto.authentic.CryptoHelp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Random;


@Component("cryptocontextholder")
public class CryptoContextHolder {
    private final CertProvImpl certProv;
    Logger log = LoggerFactory.getLogger(getClass());
    private final PlatformLogger logger = PlatformLogger.getInstance();
    @Autowired
    private ThreadLocal<PlatformLogger.Meta> metaThreadLocal;
    private Long context = 0L;

    public CryptoContextHolder(CertProvImpl certProv) {
        this.certProv = certProv;
        if (metaThreadLocal == null) metaThreadLocal = new ThreadLocal<>();
        if (metaThreadLocal.get() == null) metaThreadLocal.set(logger.newMeta().pid(Math.abs(new Random().nextLong())));
        logger.meta(this.metaThreadLocal.get())
            .debug("Initializing CryptoContextHolder by CertProvImpl");

        try {
            log.info("Crypto Context with handler: {} initialized START", this.context);
            this.context = CryptoHelp.initContext(true, certProv);
            CryptoHelp.set_log_level(context, 8);
            log.info("Crypto Context with handler: {} initialized OK", this.context);
            logger.meta(this.metaThreadLocal.get())
                .trace("Crypto Context with handler: {} initialized OK", this.context);
        } catch (Exception e) {
            logger.meta(this.metaThreadLocal.get())
                .warn("Error while Initializing CryptoContextHolder e : {}", e.getMessage());
            log.error(e.getMessage());
            this.context = 0L;
        }
    }

    public long getContext() {
        return this.context;
    }
}
