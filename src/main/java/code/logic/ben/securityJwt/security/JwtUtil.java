package code.logic.ben.securityJwt.security;

import code.logic.ben.securityJwt.entity.Role;
import code.logic.ben.securityJwt.entity.User;
import code.logic.ben.securityJwt.repository.UserRepository;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Data
@AllArgsConstructor
@RequiredArgsConstructor

@Component
public class JwtUtil {

    //    Secret Key
    private static final SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    //    Expiration time in milliseconds
    private final int jwtExpirationMs = 86400000;

    @Autowired
    UserRepository userRepository;

    public String generateToken(String username) {
        Optional<User> user = userRepository.findByUsername(username);
        Set<Role> roles = user.get().getRoles();

//        Add roles to the token

        return Jwts.builder().setSubject(username).claim("roles", roles.stream()
                        .map(role -> role.getName()).collect(Collectors.joining(",")))
                .setIssuedAt(new Date()).setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(secretKey).compact();

    }

//    Extract Username

    public String extractUsername(String token) {
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJwt(token).getBody().getSubject();
    }

//    Extract Roles

    public Set<String> extractRoles(String token) {
        String rolesString = Jwts.parserBuilder().setSigningKey(secretKey)
                .build().parseClaimsJwt(token).getBody().get("roles", String.class);

        return Set.of(rolesString);
    }

//    Token Validation

    public boolean isTokenValid(String token){
        try{
            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJwt(token);
            return true;
        }
        catch (JwtException | IllegalArgumentException e){
            return false;
        }
    }


}
