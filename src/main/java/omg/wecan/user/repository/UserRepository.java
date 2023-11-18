package omg.wecan.user.repository;

import omg.wecan.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;



public interface UserRepository extends JpaRepository<User, Integer> {
    public User findByEmail(String email);
}
