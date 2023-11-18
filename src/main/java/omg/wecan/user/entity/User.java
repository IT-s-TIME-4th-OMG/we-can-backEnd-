package omg.wecan.user.entity;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "user")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long user_id;

    private String email;
    private String password;
    private String name;
    private String nickname;
    private String phone;
    private String img_endpoint;
    private int candy;
    private boolean social;
    private String refresh_token;


}
