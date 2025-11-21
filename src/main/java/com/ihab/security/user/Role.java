package com.ihab.security.user;


import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.ihab.security.user.Permission.*;
import static com.ihab.security.user.Permission.MANAGER_CREATE;
import static com.ihab.security.user.Permission.MANAGER_DELETE;

@RequiredArgsConstructor
public enum Role {
    USER(Collections.emptySet()),
    ADMIN(
            Set.of(
                    ADMIN_READ,
                    ADMIN_UPDATE,
                    ADMIN_CREATE,
                    ADMIN_DELETE,
                    MANAGER_UPDATE,
                    MANAGER_READ,
                    MANAGER_CREATE,
                    MANAGER_DELETE
            )
    ),
    MANAGER(
            Set.of(
                    MANAGER_UPDATE,
                    MANAGER_READ,
                    MANAGER_CREATE,
                    MANAGER_DELETE
            )
    );

    @Getter
    private final Set<Permission> permissions;

    /*----- this one to get specific permission and transfer it to object -----*/
    public List<SimpleGrantedAuthority> getAuthorities(){
        var authorities =  getPermissions().stream().map(
                // permission.name() isn't working because it will return MANGER_UPDATE
                // but we need manager:update
                permission -> new SimpleGrantedAuthority(permission.getPermission())
        ).collect(Collectors.toList());
        /*----- this use to define which role -----*/
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
    return authorities;
    }
/* it will be like
* [admin:read, admin:write .....and so on
* then ROLE_ADMIN ]*/

}
