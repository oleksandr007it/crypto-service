package com.idevhub.exceptions;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.idevhub.crypto.service.enums.CryptoServiceError;
import com.idevhub.exceptions.dto.CryptoServiceServiceErrorVM;
import feign.Response;
import feign.codec.ErrorDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class CryptoServiceErrorDecoder implements ErrorDecoder {
    private final Logger logger = LoggerFactory.getLogger(CryptoServiceErrorDecoder.class);

    private ErrorDecoder fallbackErrorDecoder = new ErrorDecoder.Default();

    @Autowired
    private ObjectMapper mapper;

    private static String responseBodyToString(Response response) throws IOException {
        InputStream inputStream = response.body().asInputStream();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int nRead;
        byte[] data = new byte[1024];
        while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }

        buffer.flush();
        byte[] byteArray = buffer.toByteArray();

        String text = new String(byteArray, StandardCharsets.UTF_8);
        return text;
    }

    @Override
    public Exception decode(String s, Response response) {
        // get only our exception
        if (response.body() != null && response.status() == CryptoServiceException.httpStatus.value()) {
            String body = "";
            try {
                body = responseBodyToString(response);
                logger.debug("decode http status: {} body: {}", response.status(), body);
                // extract error body JSON to model
                CryptoServiceServiceErrorVM errorVM = mapper.readValue(body, CryptoServiceServiceErrorVM.class);

                // generate business exception from the Json body
                return new CryptoServiceException(errorVM.getError(), errorVM.getMessage());

            } catch (IOException e) {
                return new CryptoServiceException(
                    CryptoServiceError.GenericError,
                    "can't deserialize response body to SvcPositionServiceErrorVM: " + body);
            }
        }

        // forward to default decoder
        return fallbackErrorDecoder.decode(s, response);
    }
}
