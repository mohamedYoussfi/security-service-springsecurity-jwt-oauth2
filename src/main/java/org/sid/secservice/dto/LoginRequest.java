package org.sid.secservice.dto;

public record LoginRequest(
        String grantType,
        String username,
        String password,
        boolean withRefreshToken,
        String refreshToken
        ) {
}
