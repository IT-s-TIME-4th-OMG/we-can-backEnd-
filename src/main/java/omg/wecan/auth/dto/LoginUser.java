package omg.wecan.auth.dto;

public class LoginUser {

    private Long id;

    private LoginUser() {
    }

    public LoginUser(final Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }
}