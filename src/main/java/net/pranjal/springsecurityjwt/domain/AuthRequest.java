package net.pranjal.springsecurityjwt.domain;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AuthRequest {
    private String userName;
    private String password;
}
