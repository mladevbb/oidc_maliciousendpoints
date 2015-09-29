package de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.controller;

import de.rub.nds.oidc.attacks.oidc_maliciousdiscoveryservice.utils.InterceptedData;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author vladi
 */
@ManagedBean(name="database")
@ViewScoped
public class Database implements Serializable{
    private static final Logger log = LoggerFactory.getLogger(Database.class);
    private List<InterceptedData> interceptedTokens;
    private InterceptedData lastEntry;
    
    private String webfingerAsString;
    private String openidConfigAsString;
    
    private String configIssuer;
    private String configRegEndpoint;
    private String configTokenEndpoint;
    private String configAuthEndpoint;
    private String configUserInfoEndpoint;
    private String configRevocationEndpoint;
    private String jwksEndpoint;
    

    public Database() {
        readLog();
        
        if (interceptedTokens == null){
            interceptedTokens = new ArrayList<>();
        }
    }
    

    public List<InterceptedData> getInterceptedTokens() {
        return interceptedTokens;
    }

    public void setInterceptedTokens(List<InterceptedData> interceptedTokens) {
        this.interceptedTokens = interceptedTokens;
    }
    
    
    public void addInterceptedToken(InterceptedData interceptedData){
        lastEntry = interceptedData;
        interceptedTokens.add(0,interceptedData);
        updateLog();
    }
    
    private void updateLog() {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(ConfigurationManager.getCfgManager().getLogFile(), false);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(interceptedTokens);
            oos.close();
        } catch (IOException ex) {
            log.error(ex.getMessage(), ex);
        } finally {
            try {
                fos.close();
            } catch (IOException | NullPointerException ex) {
                log.error(ex.getMessage(), ex);
            }
        }
    }

    private void readLog() {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(ConfigurationManager.getCfgManager().getLogFile());
            ObjectInputStream ois = new ObjectInputStream(fis);
            interceptedTokens=  (List<InterceptedData>) ois.readObject();
            ois.close();
        } catch (IOException | ClassNotFoundException ex) {
            log.error(ex.getMessage(), ex);
        } finally {
            try {
                fis.close();
            } catch (IOException | NullPointerException ex) {
                log.error(ex.getMessage(), ex);
            }
        }
    }

    public InterceptedData getLastEntry() {
        return lastEntry;
    }

    public void setLastEntry(InterceptedData lastEntry) {
        this.lastEntry = lastEntry;
    }
    
    public String getWebfingerAsString() {
        return webfingerAsString;
    }

    public void setWebfingerAsString(String webfingerAsString) {
        this.webfingerAsString = webfingerAsString;
    }

    public String getOpenidConfigAsString() {
        return openidConfigAsString;
    }

    public void setOpenidConfigAsString(String openidConfigAsString) {
        this.openidConfigAsString = openidConfigAsString;
    }

    public String getConfigIssuer() {
        return configIssuer;
    }

    public void setConfigIssuer(String configIssuer) {
        this.configIssuer = configIssuer;
    }

    public String getConfigRegEndpoint() {
        return configRegEndpoint;
    }

    public void setConfigRegEndpoint(String configRegEndpoint) {
        this.configRegEndpoint = configRegEndpoint;
    }

    public String getConfigTokenEndpoint() {
        return configTokenEndpoint;
    }

    public void setConfigTokenEndpoint(String configTokenEndpoint) {
        this.configTokenEndpoint = configTokenEndpoint;
    }

    public String getConfigAuthEndpoint() {
        return configAuthEndpoint;
    }

    public void setConfigAuthEndpoint(String configAuthEndpoint) {
        this.configAuthEndpoint = configAuthEndpoint;
    }

    public String getConfigUserInfoEndpoint() {
        return configUserInfoEndpoint;
    }

    public void setConfigUserInfoEndpoint(String configUserInfoEndpoint) {
        this.configUserInfoEndpoint = configUserInfoEndpoint;
    }

    public String getConfigRevocationEndpoint() {
        return configRevocationEndpoint;
    }

    public void setConfigRevocationEndpoint(String configRevocationEndpoint) {
        this.configRevocationEndpoint = configRevocationEndpoint;
    }

    public String getJwksEndpoint() {
        return jwksEndpoint;
    }

    public void setJwksEndpoint(String jwksEndpoint) {
        this.jwksEndpoint = jwksEndpoint;
    }
    
    public void clearLastEntry(){
        lastEntry = null;
    }
}
