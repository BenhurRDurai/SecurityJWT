package code.logic.ben.securityJwt.controller;

import code.logic.ben.securityJwt.dto.RegisterRequest;
import code.logic.ben.securityJwt.entity.Role;
import code.logic.ben.securityJwt.entity.User;
import code.logic.ben.securityJwt.repository.RoleRepository;
import code.logic.ben.securityJwt.repository.UserRepository;
import code.logic.ben.securityJwt.security.JwtUtil;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashSet;
import java.util.Set;



@RequiredArgsConstructor

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

//    Regiser user API
    @PostMapping("/register") // Register endpoint http://localhost:9090/auth/register
    public ResponseEntity<String> register(@RequestBody RegisterRequest registerRequest){

        if(userRepository.findByUsername(registerRequest.getUsername()).isPresent()){
            return ResponseEntity.badRequest().body("Username is already taken");
        }

        User newUser = new User();
        newUser.setUsername(registerRequest.getUsername());

        String encodedPassword = passwordEncoder.encode(registerRequest.getPassword());
        newUser.setPassword(encodedPassword);
        System.out.println("Encoded password : " + encodedPassword);

//        convert role names to role entities and assign to user
        Set<Role> roles = new HashSet<>();
        for(String roleName: registerRequest.getRoles()){
            Role role = roleRepository.findByName(roleName).orElseThrow(() -> new RuntimeException("Role not found " + roleName));
            roles.add(role);

        }

        newUser.setRoles(roles);
        userRepository.save(newUser);
        return ResponseEntity.ok("User Registered Successfully");
    }


//    Login API - //Login endpoint http://localhost:9090/auth/login
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody User loginRequest){

        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword()));
        } catch (Exception e) {
            System.out.println("Exception: " + e);;
        }
        String token = jwtUtil.generateToken(loginRequest.getUsername());
        return ResponseEntity.ok(token);

    }

}
