package org.sid.secservice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
public class MyRestAPI {
    @GetMapping("/infos")
    @PreAuthorize("hasAuthority('SCOPE_USER')")
    public Map<String,Object> dataTest(Principal principal, Authentication authentication){
        return Map.of("name","Compuer","price",7600,"username",principal.getName(),"authorities",authentication.getAuthorities());
    }
}
