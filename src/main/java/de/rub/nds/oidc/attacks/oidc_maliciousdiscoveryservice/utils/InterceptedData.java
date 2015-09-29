package de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.utils;

import java.io.Serializable;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

/**
 *
 * @author vladi
 */
public class InterceptedData implements Serializable {
    private String dateTime;
    private String client_id;
    private String client_secret;
    private String code;
    private String access_token;
    private String refresh_token;
    private String id_token;
    private String redirect_uri;
    private String ressources;
    private Map<String, String> httpParameters;
    private final DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
    
    public InterceptedData(String code, String client_id, String client_secret){
        this.code = code;
        this.client_id = client_id;
        this.client_secret = client_secret;
        this.dateTime = dateFormat.format(new Date());
    }
    
    public InterceptedData(String access_token){        
	this.dateTime = dateFormat.format(new Date());
        this.access_token = access_token;
    }

    public String getDateTime() {
        return dateTime;
    }

    public void setDateTime(String dateTime) {
        this.dateTime = dateTime;
    }

    public String getClient_id() {
        return client_id;
    }

    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }

    public String getClient_secret() {
        return client_secret;
    }

    public void setClient_secret(String client_secret) {
        this.client_secret = client_secret;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getAccess_token() {
        return access_token;
    }

    public void setAccess_token(String access_token) {
        this.access_token = access_token;
    }

    public String getId_token() {
        return id_token;
    }

    public void setId_token(String id_token) {
        this.id_token = id_token;
    }

    public Map<String, String> getHttpParameters() {
        return httpParameters;
    }

    public void setHttpParameters(Map<String, String> httpParameters) {
        this.httpParameters = httpParameters;
    }

    public String getRessources() {
        return ressources;
    }

    public void setRessources(String ressources) {
        this.ressources = ressources;
    }

    public String getRedirect_uri() {
        return redirect_uri;
    }

    public void setRedirect_uri(String redirect_uri) {
        this.redirect_uri = redirect_uri;
    }

    public String getRefresh_token() {
        return refresh_token;
    }

    public void setRefresh_token(String refresh_token) {
        this.refresh_token = refresh_token;
    }

}
