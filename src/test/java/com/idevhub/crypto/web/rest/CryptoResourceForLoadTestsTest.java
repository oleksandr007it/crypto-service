package com.idevhub.crypto.web.rest;

import com.idevhub.crypto.CryptoserviceApp;
import com.idevhub.model.PreSignStruct;
import com.idevhub.crypto.service.CryptoContextHolder;
import com.idevhub.crypto.service.feign.RemoteCertRepo;
import com.idevhub.model.Makep10DTO;
import com.qb.crypto.authentic.SignerInfo;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.inject.Inject;
import java.io.InputStream;
import java.util.Base64;

import static org.hamcrest.Matchers.hasItem;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = CryptoserviceApp.class)
public class CryptoResourceForLoadTestsTest {


    private static final String DATA_FOR_SIGN_BASE64 = "REFUQUZPUlNJR04=";
    private static final String CURRENT_CERT_NAME = "00C5B0617EE63989BCACB4C513DC399EF6D4E3DEC4472F415965FD91A2DCD6D6.cer";
    private static final String CURRENT_CERT_ECDSA__NAME = "311C4527A7CF00276F7CC31C16A7C6FAA07BEB33C4B8BAD573FA004B063CD84F.cer";
    private static final String SUBJECT_KEY_IDENTIFIER = "00C5B0617EE63989BCACB4C513DC399EF6D4E3DEC4472F415965FD91A2DCD6D6";
    private static final String SUBJECT_INFO_XML = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPGNvbmZpZz4KICA8IS0tICDC5fDx6P8g9ODp6+Ag7eDx8vDu5eotLT4KICA8VmVyc2lvbiB2ZXJzaW9uPSIwLjEuMC4wIi8+CiAgPFBLST4KICAgIDxUb2tlbk1hbmFnZXI+CiAgICAgIDxTdWJqZWN0SW5mbz4KICAgICAgICA8U3ViamVjdE5hbWUgb3JnYW5pemF0aW9uTmFtZT0i1M7PINbg7+ruIMTl7ejxIM/l8vDu4uj3Ii8+CiAgICAgICAgPFN1YmplY3ROYW1lIHRpdGxlPSLUs+fo9+3gIO7x7uHgLe+z5O/w6Lrs5fb8Ii8+CiAgICAgICAgPFN1YmplY3ROYW1lIGNvbW1vbk5hbWU9Itbg7+ruIMTl7ejxIM/l8vDu4uj3Ii8+CiAgICAgICAgPFN1YmplY3ROYW1lIHN1cm5hbWU9Itbg7+ruIi8+CiAgICAgICAgPFN1YmplY3ROYW1lIGdpdmVuTmFtZT0ixOXt6PEgz+Xy8O7i6PciLz4KICAgICAgICA8U3ViamVjdE5hbWUgc2VyaWFsTnVtYmVyPSJVQS03Nzc3Nzc3NzctMjAxNyIvPgogICAgICAgIDxTdWJqZWN0TmFtZSBjb3VudHJ5TmFtZT0iVUEiLz4KICAgICAgICA8U3ViamVjdE5hbWUgbG9jYWxpdHlOYW1lPSLsLiDK6L/iIi8+CiAgICAgICAgPEFsZ29yaXRobUlkZW50aWZpZXIgbmFtZWRDdXJ2ZT0iMS4yLjgwNC4yLjEuMS4xLjEuMy4xLjEuMi42Ii8+CiAgICAgIDwvU3ViamVjdEluZm8+CiAgICAgIDxFeHRlbnNpb24+CiAgICAgICAgPFVzZXJQcmluY2lwYWxOYW1lIFVQTj0iVVBOLTEuMy42LjEuNC4xLjMxMS4yMC4yLjMiLz4KICAgICAgICA8TG9jYXRpb24gbG9jYXRpb249IjA0NTQ1LCDS5fHy7uLgICDu4esuLCDsLiDS5fHy7uLlLCDi8+suINjl4vfl7ergLCA1IMAsIO70LiA0NSAiLz4KICAgICAgICA8VXNlckNvZGUgY29kZT0iMTExMTExMTExMSIvPiAgICAgCiAgICAgICAgICAgICAgICA8T2twb0NvZGUgY29kZT0iNzc3Nzc3Nzc3Ii8+ICAgICAKICAgICAgICAgICAgICAgIDxQaG9uZU51bWJlciBudW1iZXI9IjM4MDczMTAwMjQzMSIvPiAgICAgIAogICAgICA8L0V4dGVuc2lvbj4KICAgIDwvVG9rZW5NYW5hZ2VyPgogIDwvUEtJPgo8L2NvbmZpZz4=";
    private static final String SUBJECT_ECDSA_XML = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPGNvbmZpZz4KICA8IS0tICDC5fDx6P8g9ODp6+Ag7eDx8vDu5eotLT4KICA8VmVyc2lvbiB2ZXJzaW9uPSIwLjEuMC4wIi8+CiAgPFBLST4KICAgIDxUb2tlbk1hbmFnZXI+CiAgICAgIDxTdWJqZWN0SW5mbz4KICAgICAgICA8U3ViamVjdE5hbWUgb3JnYW5pemF0aW9uTmFtZT0i0s7CINDu4+Ag6CDq7u/78uAiLz4KICAgICAgICA8U3ViamVjdE5hbWUgdGl0bGU9IsTo8OXq8u7wIi8+CiAgICAgICAgPFN1YmplY3ROYW1lIGNvbW1vbk5hbWU9IrLi4O3u4iCy4uDtILLi4O3u4uj3Ii8+CiAgICAgICAgPFN1YmplY3ROYW1lIHN1cm5hbWU9IrLi4O3u4iIvPgogICAgICAgIDxTdWJqZWN0TmFtZSBnaXZlbk5hbWU9IrLi4O0gsuLg7e7i6PciLz4KICAgICAgICA8U3ViamVjdE5hbWUgc2VyaWFsTnVtYmVyPSI1MDM0ODUiLz4KICAgICAgICA8U3ViamVjdE5hbWUgY291bnRyeU5hbWU9IlVBIi8+CiAgICAgICAgPFN1YmplY3ROYW1lIGxvY2FsaXR5TmFtZT0i7C4gyui/4iIvPgogICAgICAgIDxBbGdvcml0aG1JZGVudGlmaWVyIG5hbWVkQ3VydmU9IjEuMi44NDAuMTAwNDUuMy4xLjciLz4KICAgICAgPC9TdWJqZWN0SW5mbz4KICAgICAgPEV4dGVuc2lvbj4KICAgICAgICA8VXNlclByaW5jaXBhbE5hbWUgVVBOPSJVUE4tMS4zLjYuMS40LjEuMzExLjIwLjIuMyIvPgogICAgICAgIDxMb2NhdGlvbiBsb2NhdGlvbj0iMDQ1NDUsINLl8fLu4uAgIO7h6y4sIOwuINLl8fLu4uUsIOLz6y4g2OXi9+Xt6uAsIDUgwCwg7vQuIDQ1IDEuMy42LjEuNC4xLjE5Mzk4LjEuMS40LjIiLz4KICAgICAgICA8VXNlckNvZGUgY29kZT0iMS4yLjgwNC4yLjEuMS4xLjExLjEuNC4xLjEiLz4gICAgIAoJPE9rcG9Db2RlIGNvZGU9IjEuMi44MDQuMi4xLjEuMS4xMS4xLjQuMi4xIi8+ICAgICAKCTxQaG9uZU51bWJlciBudW1iZXI9IjM4MDczMTAwMjQzMSIvPiAgICAgIAogICAgICA8L0V4dGVuc2lvbj4KICAgIDwvVG9rZW5NYW5hZ2VyPgogIDwvUEtJPgo8L2NvbmZpZz4=";

    private MockMvc restCryptoMockMvc;
    private byte[] currentCert;

    @Mock
    private RemoteCertRepo remoteCertRepo;


    @Inject
    private CryptoContextHolder cryptoContextHolder;

    private CryptoResource cryptoResource;
    private CryptoResource spycryptoResource;
    private PreSignStruct preSignStruct;
    private String dataHashBase64;
    private String rawSignBase64;
    private String signatureBase64;
    private final int digitalSignature = 1;
    private Short algorithm = 0;
    private final int nonRepudiation = 1 << 1;
    private int keyUsage = digitalSignature | nonRepudiation;
    private SignerInfo signerInfo;
    private String publicKeyBase64;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        this.cryptoResource = new CryptoResource(remoteCertRepo, cryptoContextHolder);
        InputStream stream = getInputStreamFromResourceByName(CURRENT_CERT_NAME);
        this.currentCert = IOUtils.toByteArray(stream);
        this.spycryptoResource = spy(this.cryptoResource);
        doReturn(this.currentCert).when(spycryptoResource).getCertByAcskAndSerialNumber(any(String.class), any(String.class));
        this.restCryptoMockMvc = MockMvcBuilders.standaloneSetup(spycryptoResource).build();
        this.dataHashBase64 = spycryptoResource.getAuthenticHashByPhone(DATA_FOR_SIGN_BASE64, "1", "2");
        this.preSignStruct = spycryptoResource.getAuthenticMakeHash_ex(this.dataHashBase64, "1", "2");
        byte[] rawSign = TestUtil.mackeRawSin(Base64.getDecoder().decode(preSignStruct.getHashToCmsBase64()));
        rawSignBase64 = Base64.getEncoder().encodeToString(rawSign);
        signatureBase64 = spycryptoResource.authenticMakeCmsSign2_ex("1", "2",
            dataHashBase64, rawSignBase64, preSignStruct.getHashToCmsWithCashBase64());

        signerInfo = spycryptoResource.authenticGetSignerinfo(Base64.getEncoder().encodeToString(currentCert));
        byte[] decodedHex = Hex.decodeHex(signerInfo.getPublic_key_().toCharArray());
        publicKeyBase64 = Base64.getEncoder().encodeToString(decodedHex);


    }

    private InputStream getInputStreamFromResourceByName(String resourceName) {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        return loader.getResourceAsStream(resourceName);
    }


    @Test
    public void getAuthenticHashByPhone() throws Exception {
        restCryptoMockMvc.perform(post("/api/authentichash?dataBase64=" + DATA_FOR_SIGN_BASE64 + "&acsk=1&serialNumber=2")).andExpect(status().isOk());
    }

    @Test
    public void getAuthenticMakeHash_ex() throws Exception {
        restCryptoMockMvc.perform(post("/api/authenticmakehash/?dataHashBase64=" + this.dataHashBase64 + "&acsk=1&serialNumber=2"))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8_VALUE))
            .andExpect(jsonPath("$.hashToCmsBase64").exists())
            .andExpect(jsonPath("$.hashToCmsWithCashBase64").exists());

    }

    @Test
    public void authenticGetSignerinfo() throws Exception {
        String currentCertBase64 = Base64.getEncoder().encodeToString(this.currentCert);
        restCryptoMockMvc.perform(post("/api/authenticgetsignerinfo?certBase64=" + currentCertBase64 + "&acsk=1&serialNumber=2")).andExpect(status().isOk());
    }

    @Test
    public void authenticMakeCmsSign2_ex() throws Exception {

        restCryptoMockMvc.perform(post("/api/authenticmakecmssign2?acsk=1&serialNumber=2&dataHashBase64="
            + this.dataHashBase64 + "&rawSignBase64=" + rawSignBase64 + "&hashToCmsWithCash=" + preSignStruct.getHashToCmsWithCashBase64())).andExpect(status().isOk());
    }

    @Test
    public void getAuthenticVerify() throws Exception {

        restCryptoMockMvc.perform(post("/api/authenticverify?dataBase64="
            + DATA_FOR_SIGN_BASE64 + "&base64Value=" + signatureBase64)).andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8_VALUE))
            .andExpect(jsonPath("$.subject_key_identifier_").value(SUBJECT_KEY_IDENTIFIER.toString()));

    }

    @Test
    public void authenticverifybyhash() throws Exception {
        restCryptoMockMvc.perform(post("/api/authenticverifybyhash?dataHashBase64=" + dataHashBase64 + "&signatureBase64=" + signatureBase64))
            .andExpect(status().isOk());
    }

    @Test
    public void authenticverifyreturnhas() throws Exception {
        restCryptoMockMvc.perform(post("/api/authenticverifyreturnhash?&signatureBase64=" + signatureBase64))
            .andExpect(status().isOk()).andExpect(content().string(dataHashBase64));
    }

    @Test
    public void authenticmakep10step1() throws Exception {
        Makep10DTO makep10DTO = new Makep10DTO();
        makep10DTO.setKeyUsage(keyUsage);
        makep10DTO.setPublicKeyBase64(publicKeyBase64);
        makep10DTO.setSubjectInfoFileBase64(SUBJECT_INFO_XML);
        restCryptoMockMvc.perform(post("/api/authenticmakep10step1")
            .contentType(TestUtil.APPLICATION_JSON_UTF8)
            .content(TestUtil.convertObjectToJsonBytes(makep10DTO)))
            .andExpect(status().isOk());

    }

    @Test
    public void authenticmakep10step2() throws Exception {
        Makep10DTO makep10DTO = new Makep10DTO();
        makep10DTO.setKeyUsage(keyUsage);
        makep10DTO.setPublicKeyBase64(publicKeyBase64);
        makep10DTO.setSubjectInfoFileBase64(SUBJECT_INFO_XML);
        String step1Base64 = spycryptoResource.authenticmakep10step1(makep10DTO);
        String hashSignP10Base64 = spycryptoResource.getAuthenticPksc10hash(step1Base64, (short) 1);
        byte[] rawSignP10 = TestUtil.mackeRawSin(Base64.getDecoder().decode(hashSignP10Base64));
        String rawSignP10Base64 = Base64.getEncoder().encodeToString(rawSignP10);
        makep10DTO.setSignatureForP10Base64(rawSignP10Base64);
        restCryptoMockMvc.perform(post("/api/authenticmakep10step2")
            .contentType(TestUtil.APPLICATION_JSON_UTF8)
            .content(TestUtil.convertObjectToJsonBytes(makep10DTO)))
            .andExpect(status().isOk());


    }

}
