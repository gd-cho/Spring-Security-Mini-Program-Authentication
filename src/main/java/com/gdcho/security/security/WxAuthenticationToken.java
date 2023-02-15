package com.gdcho.security.security;

import com.gdcho.security.entity.vo.UserPrincipal;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
@Setter
public class WxAuthenticationToken extends AbstractAuthenticationToken {

    private UserPrincipal userPrincipal;

    private boolean isWx;


    public WxAuthenticationToken(UserPrincipal userPrincipal,
                                 boolean isWx) {
        super(null);
        this.userPrincipal = userPrincipal;
        this.isWx = isWx;

    }


    public WxAuthenticationToken(UserPrincipal userPrincipal,
                                 boolean isWx,
                                 Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.isWx = isWx;
        this.userPrincipal = userPrincipal;
        super.setAuthenticated(true);
    }

    /**
     * 未验证微信登录
     */
    public static WxAuthenticationToken unauthenticatedWx(UserPrincipal userPrincipal) {
        return new WxAuthenticationToken(userPrincipal, true);
    }

    /**
     * 已验证微信登录
     */
    public static WxAuthenticationToken authenticatedWx(UserPrincipal userPrincipal,
                                                        Collection<? extends GrantedAuthority> authorities) {

        return new WxAuthenticationToken(userPrincipal, true, authorities);
    }

    /**
     * 未验证普通登录
     */
    public static WxAuthenticationToken unauthenticated(UserPrincipal userPrincipal) {
        return new WxAuthenticationToken(userPrincipal, false);
    }

    /**
     * 已验证普通登录
     */
    public static WxAuthenticationToken authenticated(UserPrincipal userPrincipal,
                                                      Collection<? extends GrantedAuthority> authorities) {
        return new WxAuthenticationToken(userPrincipal, false, authorities);
    }


    @Override
    public Object getPrincipal() {
        return this.userPrincipal.getUsername();
    }

    @Override
    public Object getCredentials() {
        return this.userPrincipal.getPassword();
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        super.setAuthenticated(isAuthenticated);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }
}
