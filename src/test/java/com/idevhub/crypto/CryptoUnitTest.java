package com.idevhub.crypto;

import com.idevhub.model.PreSignStruct;
import com.idevhub.crypto.service.CryptoContextHolder;
import com.idevhub.crypto.service.feign.RemoteCertRepo;
import com.idevhub.crypto.web.rest.CryptoResource;
import com.idevhub.crypto.web.rest.TestUtil;
import com.qb.crypto.authentic.SignerInfo;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.inject.Inject;
import java.io.InputStream;
import java.util.Base64;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.junit.Assert.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = CryptoserviceApp.class)
public class CryptoUnitTest {


    private static final String DATA_FOR_SIGN = "REFUQUZPUlNJR04=";
    private static final String CURRENT_CERT_NAME = "00C5B0617EE63989BCACB4C513DC399EF6D4E3DEC4472F415965FD91A2DCD6D6.cer";
    private static final String SUBJECT_KEY_IDENTIFIER = "00C5B0617EE63989BCACB4C513DC399EF6D4E3DEC4472F415965FD91A2DCD6D6";

    private MockMvc restCryptoMockMvc;
    private byte[] currentCert;

    @Mock
    private RemoteCertRepo remoteCertRepo;


    @Inject
    private CryptoContextHolder cryptoContextHolder;
    private CryptoResource cryptoResource;
    private CryptoResource spycryptoResource;
    private PreSignStruct preSignStruct;
    private Short algorithm = 0;
    private String dataHashBase64;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        this.cryptoResource = new CryptoResource(remoteCertRepo, cryptoContextHolder);
        InputStream stream = getInputStreamFromResourceByName(CURRENT_CERT_NAME);
        this.currentCert = IOUtils.toByteArray(stream);
        this.spycryptoResource = spy(this.cryptoResource);
        doReturn(this.currentCert).when(spycryptoResource).getCertByAcskAndSerialNumber(any(String.class), any(String.class));
        this.restCryptoMockMvc = MockMvcBuilders.standaloneSetup(spycryptoResource).build();
        this.dataHashBase64 = spycryptoResource.getAuthenticHashByPhone(DATA_FOR_SIGN, "1", "2");
        this.preSignStruct = spycryptoResource.getAuthenticMakeHash_ex(this.dataHashBase64, "1", "2");

    }


    private InputStream getInputStreamFromResourceByName(String resourceName) {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        return loader.getResourceAsStream(resourceName);
    }

    @Test
    public void getAuthenticHashByPhone() throws Exception {
        restCryptoMockMvc.perform(post("/api/authentichash/?dataBase64=" + DATA_FOR_SIGN + "&acsk=1&serialNumber=2")).andExpect(status().isOk());
    }

    @Test
    public void getAuthenticMakeHash_ex() throws Exception {
        restCryptoMockMvc.perform(post("/api/authenticmakehash/?dataHashBase64=" + this.dataHashBase64 + "&acsk=1&serialNumber=2")).andExpect(status().isOk());
    }

    @Test
    public void getauthenticp10hash() throws Exception {
        restCryptoMockMvc.perform(post("/api/authenticp10hash/?dataBase64=" + DATA_FOR_SIGN + "&codeAlgorithm=0")).andExpect(status().isOk());
    }

    @Test
    public void authenticGetSignerinfo() throws Exception {
        SignerInfo signerInfo = spycryptoResource.authenticGetSignerinfo(Base64.getEncoder().encodeToString(currentCert));
        assertThat(signerInfo.getSubject_key_identifier_(), equalTo(SUBJECT_KEY_IDENTIFIER));

    }

    @Test
    public void authenticMakeCmsSign2_ex() throws Exception {
        byte[] rawSign = TestUtil.mackeRawSin(Base64.getDecoder().decode(preSignStruct.getHashToCmsBase64()));
        String signatureBase64 = spycryptoResource.authenticMakeCmsSign2_ex("1", "2", this.dataHashBase64, Base64.getEncoder().encodeToString(rawSign), preSignStruct.getHashToCmsWithCashBase64());
        spycryptoResource.authenticverifybyhash(this.dataHashBase64, signatureBase64);

        SignerInfo signerInfo = spycryptoResource.getAuthenticVerify(DATA_FOR_SIGN, signatureBase64);
        String mydataHashBase64 = spycryptoResource.authenticverifyreturnhas(signatureBase64);

        assertThat(signerInfo.getSubject_key_identifier_(), equalTo(SUBJECT_KEY_IDENTIFIER));
        assertThat(mydataHashBase64, equalTo(this.dataHashBase64));
    }


}
