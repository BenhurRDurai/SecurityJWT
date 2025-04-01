package code.logic.ben.securityJwt.service;

import code.logic.ben.securityJwt.entity.User;
import code.logic.ben.securityJwt.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Data
@AllArgsConstructor

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username).orElseThrow(()-> new UsernameNotFoundException("User not found " + username));
//      Map the roles to authority
        return new org.springframework.security.core.userdetails.User(user.getUsername(),user.getPassword(),user.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toList()));
    }
}
