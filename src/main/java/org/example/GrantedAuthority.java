package org.example;

import java.io.Serializable;

public interface GrantedAuthority extends Serializable {
    String getAuthority();
}
