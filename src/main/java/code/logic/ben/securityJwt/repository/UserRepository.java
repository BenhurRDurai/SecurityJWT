package code.logic.ben.securityJwt.repository;

import code.logic.ben.securityJwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {

    Optional<User> findByUsername(String username);

}
