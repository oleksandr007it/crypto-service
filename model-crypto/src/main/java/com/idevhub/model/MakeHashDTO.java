package com.idevhub.model;

import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiModelProperty;
import org.springframework.web.bind.annotation.RequestParam;

public class MakeHashDTO {


    @ApiModelProperty(value = "Данные для хеширования в Base64.")
    private String dataBase64;
    @ApiModelProperty(value = "Серийный номер  АЦСК издателя сертификата.")
    private String acsk;
    @ApiModelProperty(value = "Серийный номер сертификата.")
    private String serialNumber;


    public MakeHashDTO() {
    }

    public MakeHashDTO(String dataBase64, String acsk, String serialNumber) {
        this.dataBase64 = dataBase64;
        this.acsk = acsk;
        this.serialNumber = serialNumber;
    }

    public String getDataBase64() {
        return dataBase64;
    }

    public void setDataBase64(String dataBase64) {
        this.dataBase64 = dataBase64;
    }

    public String getAcsk() {
        return acsk;
    }

    public void setAcsk(String acsk) {
        this.acsk = acsk;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }
}
