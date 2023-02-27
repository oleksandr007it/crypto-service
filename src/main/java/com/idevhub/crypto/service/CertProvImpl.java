package com.idevhub.crypto.service;


import com.google.common.base.Strings;
import com.idevhub.crypto.service.feign.RemoteCertRepo;
import com.idevhub.protocol.platform.service.PlatformLogger;
import com.qb.crypto.authentic.CertProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Random;

@Component("certprovimpl")
public class CertProvImpl implements CertProvider {
    Logger log = LoggerFactory.getLogger(getClass());
    private final RemoteCertRepo remoteCertRepo;
    private final PlatformLogger logger = PlatformLogger.getInstance();
    @Autowired
    private ThreadLocal<PlatformLogger.Meta> metaThreadLocal;

    public CertProvImpl(RemoteCertRepo remoteCertRepo) {
        this.remoteCertRepo = remoteCertRepo;
    }

    @Override
    public byte[][] getCerts(String id) {
        if (metaThreadLocal == null) metaThreadLocal = new ThreadLocal<>();
        if (metaThreadLocal.get() == null) metaThreadLocal.set(logger.newMeta().pid(Math.abs(new Random().nextLong())));

        logger.meta(metaThreadLocal.get())
            .debug("Start CertProvImpl remoteCertRepo.getAllCertstorageById where id : {}", id);
        log.info("Start CertProvImpl remoteCertRepo.getAllCertstorageById");
        byte[][] cets = remoteCertRepo.getAllCertstorageById(id);
        return cets;
    }

}
