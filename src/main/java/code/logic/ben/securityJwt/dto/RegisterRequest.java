package code.logic.ben.securityJwt.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor

public class RegisterRequest {
    private String username;
    private String password;
    private Set<String> roles; // A set of role names, to be passed in the request
}
