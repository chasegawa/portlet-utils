package org.jasig.security.uportal;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class UPortalPreAuthenticatedAuthenticationToken extends PreAuthenticatedAuthenticationToken {
    private static final long serialVersionUID = 1L;
    private Map<String, List<Object>> userInfoMultivalued;
    
    /**
     * Constructor used for an authentication response. The Authentication.isAuthenticated() will return true.
     * @param aPrincipal - The authenticated principal
     * @param aCredentials
     * @param anAuthorities - The granted authorities
     */
    public UPortalPreAuthenticatedAuthenticationToken(Object aPrincipal, Object aCredentials,
                    Collection<? extends GrantedAuthority> anAuthorities) {
        super(aPrincipal, aCredentials, anAuthorities);
    }

    public Map<String, List<Object>> getUserInfoMultivalued() {
        return userInfoMultivalued;
    }

    public void setUserInfoMultivalued(Map<String, List<Object>> userInfoMultivalued) {
        this.userInfoMultivalued = userInfoMultivalued;
    }

}
