package com.idevhub.model;

import io.swagger.annotations.ApiModelProperty;


public class ExternalToInternalDTO {
    @ApiModelProperty(value = "подпись без данных")
    private String externalSignBase64;
    @ApiModelProperty(value = "данные которые нужно поместить")
    private String dataSignBase64;


    public ExternalToInternalDTO() {
    }

    public String getExternalSignBase64() {
        return externalSignBase64;
    }

    public void setExternalSignBase64(String externalSignBase64) {
        this.externalSignBase64 = externalSignBase64;
    }

    public String getDataSignBase64() {
        return dataSignBase64;
    }

    public void setDataSignBase64(String dataSignBase64) {
        this.dataSignBase64 = dataSignBase64;
    }

    public ExternalToInternalDTO(String externalSignBase64, String dataSignBase64) {
        this.externalSignBase64 = externalSignBase64;
        this.dataSignBase64 = dataSignBase64;
    }
}
