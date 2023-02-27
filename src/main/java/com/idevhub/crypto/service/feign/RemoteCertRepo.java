package com.idevhub.crypto.service.feign;


import com.idevhub.crypto.client.AuthorizedFeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;


@AuthorizedFeignClient(name = "certrepo")
public interface RemoteCertRepo {

    @GetMapping(value = "/api/certstoragesbyph/{phoneNumber}")
    byte[] getCertstorageByph(@PathVariable("phoneNumber") Long phoneNumber);

    @GetMapping(value = "/api/certstoragesbysnandasck/{acsk}/{serialNumber}")
    byte[] getCertStorageByAcskAndSerialNumber(@PathVariable("acsk") String acsk, @PathVariable("serialNumber") String serialNumber);

    @GetMapping("/api/certstoragesbyid/{id}")
    byte[][] getAllCertstorageById(@PathVariable("id") String id);


}
