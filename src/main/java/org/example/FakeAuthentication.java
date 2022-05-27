package org.example;

import java.util.Collection;
import java.util.List;

public class FakeAuthentication implements Authentication{
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of((GrantedAuthority) () -> "Role_User");
    }

    @Override
    public Object getCredentials() {
        return "password";
    }

    @Override
    public Object getDetails() {
        return "details";
    }

    @Override
    public Object getPrincipal() {
        return "principal";
    }

    @Override
    public boolean isAuthenticated() {
        return false;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

    }

    @Override
    public String getName() {
        return "name";
    }
}
