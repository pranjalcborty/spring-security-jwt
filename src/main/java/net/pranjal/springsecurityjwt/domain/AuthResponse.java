package net.pranjal.springsecurityjwt.domain;

import lombok.Data;

@Data
public class AuthResponse {
    private final String jwt;
}
