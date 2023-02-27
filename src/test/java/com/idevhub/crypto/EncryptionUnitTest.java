package com.idevhub.crypto;

import com.qb.crypto.authentic.CertProviderImpl;
import com.qb.crypto.authentic.CryptoHelp;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.SystemUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Hashtable;

import static com.idevhub.crypto.web.rest.util.CryptographyLibraryUtil.getPublicKeyByCertificate;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class EncryptionUnitTest {

    private static final String DATA_TO_ENVELOP = "abra-,.***-+/cadabra latina eureka && ,. а это кирилица пошла ,. і ще українською звісно ж {}[]\\| !@#$%^&*()_+ 1234567890";
    private static final String SENDER_CERT_NAME = "00C5B0617EE63989BCACB4C513DC399EF6D4E3DEC4472F415965FD91A2DCD6D6.cer";
    private static final String RECIPIENT_CERT_NAME = "C2369411ACD379DCE1EE9B6191BE094A676457708ADEF25D3BB50DFFE8F07D7B.cer";

    private static final String HASH_MAP_DATA_NAME = "data";
    private static final String HASH_MAP_RECIPIENT_SHARED_KEY_NAME = "sharedForRecipient";
    private static final String HASH_MAP_SENDER_SHARED_KEY_NAME = "sharedForSender";

    private byte[] senderCert;
    private byte[] recipientCert;

    @Before
    public void setUp() throws Exception {

        InputStream stream = getInputStreamFromResourceByName(SENDER_CERT_NAME);
        this.senderCert = IOUtils.toByteArray(stream);

        stream = getInputStreamFromResourceByName(RECIPIENT_CERT_NAME);
        this.recipientCert = IOUtils.toByteArray(stream);

    }

    private InputStream getInputStreamFromResourceByName(String resourceName) {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        return loader.getResourceAsStream(resourceName);
    }


    @Test
    public void envelopTest() throws Exception {
        long context = CryptoHelp.initContext(false, new CertProviderImpl());
        CryptoHelp.set_log_level(context, 7);


        HashMap<String, byte[]> result = envelop(context, DATA_TO_ENVELOP.getBytes(), senderCert, recipientCert);
        CryptoHelp.authentic_free_context(context);
        byte[] envelopedData = result.get(HASH_MAP_DATA_NAME);

        assertNotNull(envelopedData);
        assertTrue(envelopedData.length > 0);
    }


    @Ignore
    @Test
    public void developTest() throws Exception {
        long context = CryptoHelp.initContext(false, new CertProviderImpl());
        CryptoHelp.set_log_level(context, 7);

        byte[] senderPubKey = getPublicKeyByCertificate(context, senderCert);
        byte[] recipientPubKey = getPublicKeyByCertificate(context, recipientCert);

        // envelop data
        HashMap<String, byte[]> result = envelop(context, DATA_TO_ENVELOP.getBytes(), senderCert, recipientCert);
        byte[] envelopedData = result.get(HASH_MAP_DATA_NAME);

        // расшифровываем сообщение сформированое на самого себя
        byte[] senderDevelopedData = CryptoHelp.authentic_develop2(context, senderPubKey, result.get(HASH_MAP_SENDER_SHARED_KEY_NAME), envelopedData);
        byte[] recipientDevelopedData = CryptoHelp.authentic_develop2(context, recipientPubKey, result.get(HASH_MAP_RECIPIENT_SHARED_KEY_NAME), envelopedData);

        CryptoHelp.authentic_free_context(context);

        assertEquals(DATA_TO_ENVELOP, new String(senderDevelopedData));
        assertEquals(DATA_TO_ENVELOP, new String(recipientDevelopedData));
    }

    private HashMap<String, byte[]> envelop(long context, byte[] data, byte[] sender_cert, byte[] recip_cert) throws Exception {
        // Метод для сравнения параметров алгоритма по сертификатам получателя и отправителя
        boolean res_compare = CryptoHelp.authentic_compare_certificate_params(context, sender_cert, recip_cert);

        if (!res_compare)
            throw new Exception("Динамическая схема соглосования ключей не потдерживается");

        byte[] senderPubKey = getPublicKeyByCertificate(context, sender_cert);
        byte[] recipientPubKey = getPublicKeyByCertificate(context, recip_cert);
        byte[] sharedForRecipient = CryptoHelp.authentic_gen_shared_key(context, recipientPubKey);
        byte[] sharedForSender = CryptoHelp.authentic_gen_shared_key(context, senderPubKey); // формируем общий секрет для того чтоб зашифровать также на самого получателя

        //Формируем хеш таблицу получателей соостоящая из публичного ключа получателя и общего секрета который был
        // получен для этого ключа на шаге выше
        Hashtable<byte[], byte[]> pub_key_shd_shared = new Hashtable<byte[], byte[]>();
        pub_key_shd_shared.put(recipientPubKey, sharedForRecipient);
        pub_key_shd_shared.put(senderPubKey, sharedForSender);

        // Формируем шифрованый конверт передав в функцию публичный ключ отправителя (нужен для того чтоб по нему
        // найти в хранилище соответствующий сертификат) и хеш таблицу с получаиелями (сертификаты этих получателей
        // должны присутствовать в хранилище)
        byte[] envelopedData = CryptoHelp.authentic_envelop_make2(context, senderPubKey, pub_key_shd_shared, data);

        HashMap<String, byte[]> result = new HashMap<>();
        result.put("data", envelopedData);
        result.put(HASH_MAP_RECIPIENT_SHARED_KEY_NAME, sharedForRecipient);
        result.put(HASH_MAP_SENDER_SHARED_KEY_NAME, sharedForSender);

        return result;
    }


    static byte[] readSmallBinaryFile(String aFileName) throws IOException {
        Path path = Paths.get(aFileName);
        return Files.readAllBytes(path);
    }

    static void writeSmallBinaryFile(byte[] aBytes, String aFileName) throws IOException {
        Path path = Paths.get(aFileName);
        Files.write(path, aBytes); //creates, overwrites
    }
}
