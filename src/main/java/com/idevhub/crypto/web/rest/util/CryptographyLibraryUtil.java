package com.idevhub.crypto.web.rest.util;

import com.qb.crypto.authentic.CryptoHelp;
import com.qb.crypto.authentic.SignerInfo;

public class CryptographyLibraryUtil {

    /**
     * этот метод можно вызывать только когда контекст крипто-либы уже проинициализирован
     */
    public static byte[] getPublicKeyByCertificate(Long context, byte[] certificate) {
        SignerInfo signerInfo = CryptoHelp.authentic_get_signer_info(context, certificate);
        return hexStringToByteArray(signerInfo.getPublic_key_());
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

}
