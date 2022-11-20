package org.sid.secservice;

import org.sid.secservice.dto.LoginRequest;
import org.sid.secservice.entities.AppUser;
import org.sid.secservice.services.AccountService;
import org.sid.secservice.services.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AuthController {
    private static final Logger LOGGER= LoggerFactory.getLogger(AuthController.class);
    private final TokenService tokenService;
    private final AccountService accountService;
    private final JwtDecoder jwtDecoder;
    private AuthenticationManager authenticationManager;

    public AuthController(TokenService tokenService, AccountService accountService, JwtDecoder jwtDecoder, AuthenticationManager authenticationManager) {
        this.tokenService = tokenService;
        this.accountService = accountService;
        this.jwtDecoder = jwtDecoder;
        this.authenticationManager = authenticationManager;
    }

    /*
    @PostMapping("/token")
    public String requestForToken(Authentication authentication){
        return tokenService.generateJwtToken(authentication);
    }
     */
    @PostMapping("/token")
    public ResponseEntity<Map<String,String>> requestForToken(LoginRequest loginRequest){
        Map<String,String > response;
        if(loginRequest.grantType().equals("password")){
            Authentication authentication=authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.username(),loginRequest.password()
                    )
            );
            response=tokenService.generateJwtToken(authentication.getName(),authentication.getAuthorities(),loginRequest.withRefreshToken());
            return ResponseEntity.ok(response);
        } else if(loginRequest.grantType().equals("refreshToken")){
            String refreshToken=loginRequest.refreshToken();
            if(refreshToken==null) {
                return new ResponseEntity<>(Map.of("error","RefreshToken Not Present"),HttpStatus.UNAUTHORIZED);
            }
            Jwt decodedJwt = jwtDecoder.decode(refreshToken);
            String username=decodedJwt.getSubject();
            AppUser appUser=accountService.findByUserName(username);
            Collection<GrantedAuthority> authorities=appUser.getAppRoles()
                        .stream()
                        .map(role->new SimpleGrantedAuthority(role.getRoleName()))
                        .collect(Collectors.toList());
            response=tokenService.generateJwtToken(appUser.getUsername(),authorities,loginRequest.withRefreshToken());
            return ResponseEntity.ok(response);
        }
        return new ResponseEntity(Map.of("error",String.format("grantType <<%s>> not supported ",loginRequest.grantType())),HttpStatus.UNAUTHORIZED);
    }
}
