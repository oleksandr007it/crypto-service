package com.idevhub.model;

import java.io.UnsupportedEncodingException;

public class SignerInfo {
    private String subject_key_identifier_;
    private String organization_name_;
    private String organization_unit_name_;
    private String givenname_;
    private String surname_;
    private String title_;
    private String locality_name_;
    private String common_name_;
    private String serial_number_;
    private String okpo_;
    private String grfl_;
    private String phone_number_;
    private String subject_name_id_;
    private String issuer_serial_number_;
    private String public_key_;
    private String signature_algorithm_;
    private String expiration_time_not_before_;
    private String expiration_time_not_after_;
    private String issuer_common_name_;
    private String signature_time_stamp_;
    private String signature_time_;


    public  String subject_key_identifier(){return subject_key_identifier_;}
    public  String subject_name_id(){return subject_name_id_;}
    public  String serial_number(){return serial_number_;}


    public String getSubject_key_identifier_() {
        return subject_key_identifier_;
    }

    public void setSubject_key_identifier_(String subject_key_identifier_) {
        this.subject_key_identifier_ = subject_key_identifier_;
    }

    public String getOrganization_name_() {
        return organization_name_;
    }

    public void setOrganization_name_(String organization_name_) {
        this.organization_name_ = organization_name_;
    }

    public String getOrganization_unit_name_() {
        return organization_unit_name_;
    }

    public void setOrganization_unit_name_(String organization_unit_name_) {
        this.organization_unit_name_ = organization_unit_name_;
    }

    public String getGivenname_() {
        return givenname_;
    }

    public void setGivenname_(String givenname_) {
        this.givenname_ = givenname_;
    }

    public String getSurname_() {
        return surname_;
    }

    public void setSurname_(String surname_) {
        this.surname_ = surname_;
    }

    public String getPublic_key_() {
        return public_key_;
    }

    public void setPublic_key_(String public_key_) {
        this.public_key_ = public_key_;
    }

    public String getTitle_() {
        return title_;
    }

    public void setTitle_(String title_) {
        this.title_ = title_;
    }

    public String getLocality_name_() {
        return locality_name_;
    }

    public void setLocality_name_(String locality_name_) {
        this.locality_name_ = locality_name_;
    }

    public String getCommon_name_() {
        return common_name_;
    }

    public void setCommon_name_(String common_name_) {
        this.common_name_ = common_name_;
    }

    public String getSerial_number_() {
        return serial_number_;
    }

    public void setSerial_number_(String serial_number_) {
        this.serial_number_ = serial_number_;
    }

    public String getOkpo_() {
        return okpo_;
    }

    public void setOkpo_(String okpo_) {
        this.okpo_ = okpo_;
    }

    public String getGrfl_() {
        return grfl_;
    }

    public void setGrfl_(String grfl_) {
        this.grfl_ = grfl_;
    }

    public String getPhone_number_() {
        return phone_number_;
    }

    public void setPhone_number_(String phone_number_) {
        this.phone_number_ = phone_number_;
    }

    public String getSubject_name_id_() {
        return subject_name_id_;
    }

    public String getIssuer_serial_number_() {
        return issuer_serial_number_;
    }

    public String getExpiration_time_not_before_() {
        return expiration_time_not_before_;
    }

    public void setExpiration_time_not_before_(String expiration_time_not_before_) {
        this.expiration_time_not_before_ = expiration_time_not_before_;
    }

    public String getExpiration_time_not_after_() {
        return expiration_time_not_after_;
    }

    public void setExpiration_time_not_after_(String expiration_time_not_after_) {
        this.expiration_time_not_after_ = expiration_time_not_after_;
    }

    public String getIssuer_common_name_() {
        return issuer_common_name_;
    }

    public void setIssuer_common_name_(String issuer_common_name_) {
        this.issuer_common_name_ = issuer_common_name_;
    }

    public String getSignature_time_stamp_() {
        return signature_time_stamp_;
    }

    public void setSignature_time_stamp_(String signature_time_stamp_) {
        this.signature_time_stamp_ = signature_time_stamp_;
    }

    public String getSignature_time_() {
        return signature_time_;
    }

    public void setSignature_time_(String signature_time_) {
        this.signature_time_ = signature_time_;
    }

    public String getSignature_algorithm_() {
        return signature_algorithm_;
    }

    public void setSignature_algorithm_(String signature_algorithm_) {
        this.signature_algorithm_ = signature_algorithm_;
    }

    public void setIssuer_serial_number_(String issuer_serial_number_) {
        this.issuer_serial_number_ = issuer_serial_number_;
    }

    public void setSubject_name_id_(String subject_name_id_) {
        this.subject_name_id_ = subject_name_id_;
    }

    public static String ConvertToStr(byte[] sources) throws UnsupportedEncodingException {

        if (isWindows())
            return new String(sources, "CP1251");
        else
            return new String(sources, "UTF8");
    }

    public SignerInfo(byte[] subject_key_identifier,
                      byte[] organization_name,
                      byte[] organization_unit_name,
                      byte[] givenname,
                      byte[] surname,
                      byte[] title,
                      byte[] locality_name,
                      byte[] common_name,
                      byte[] serial_number,
                      byte[] okpo,
                      byte[] grfl,
                      byte[] phone_number,
                      byte[] subject_name_id,
                      byte[] issuer_serial_number,
                      byte[] public_key,
                      byte[] signature_algorithm,
                      byte[] expiration_time_not_before,
                      byte[] expiration_time_not_after,
                      byte[] issuer_common_name,
                      byte[] signature_time_stamp,
                      byte[] signature_time
    )
    {
        try {

            if (subject_key_identifier != null)
                subject_key_identifier_ = ConvertToStr(subject_key_identifier);
            if (organization_name != null)
                organization_name_ = ConvertToStr(organization_name);
            if (organization_unit_name != null)
                organization_unit_name_ = ConvertToStr(organization_unit_name);
            if (givenname != null)
                givenname_ = ConvertToStr(givenname);
            if (surname != null)
                surname_ = ConvertToStr(surname);
            if (title != null)
                title_ = ConvertToStr(title);
            if (locality_name != null)
                locality_name_ = ConvertToStr(locality_name);
            if (common_name != null)
                common_name_ = ConvertToStr(common_name);
            if (serial_number != null)
                serial_number_ = ConvertToStr(serial_number);
            if (okpo != null)
                okpo_ = ConvertToStr(okpo);
            if (grfl != null)
                grfl_ = ConvertToStr(grfl);
            if (phone_number != null)
                phone_number_ = ConvertToStr(phone_number);
            if (subject_name_id != null)
                subject_name_id_ = ConvertToStr(subject_name_id);
            if (issuer_serial_number != null)
                issuer_serial_number_ = ConvertToStr(issuer_serial_number);
            if (public_key != null)
                public_key_ = ConvertToStr(public_key);
            if (signature_algorithm != null)
                signature_algorithm_ = ConvertToStr(signature_algorithm);
            if(expiration_time_not_before != null)
                expiration_time_not_before_ = ConvertToStr(expiration_time_not_before);
            if(expiration_time_not_after != null)
                expiration_time_not_after_ =ConvertToStr(expiration_time_not_after);
            if(issuer_common_name != null)
                issuer_common_name_ = ConvertToStr(issuer_common_name);
            if(signature_time_stamp != null)
                signature_time_stamp_ =ConvertToStr(signature_time_stamp);
            if(signature_time != null)
                signature_time_ = ConvertToStr(signature_time);


        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

    }

    public static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().indexOf("win") >= 0;
    }

}
