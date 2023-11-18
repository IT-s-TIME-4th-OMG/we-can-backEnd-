package omg.wecan.user.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import omg.wecan.auth.dto.authResponse.AuthResponse;
import omg.wecan.infrastructure.oauth.basic.dto.response.OauthResponse;
import omg.wecan.jwt.domain.AuthToken;
import omg.wecan.jwt.service.JWTService;
import omg.wecan.user.dto.CertificationMailOutput;
import omg.wecan.user.dto.NewPasswordInput;
import omg.wecan.user.dto.UserCertificationInput;
import omg.wecan.user.dto.request.SignInDto;
import omg.wecan.user.dto.request.SignUpDto;
import omg.wecan.user.entity.User;
import omg.wecan.user.service.UserFindPasswordService;
import omg.wecan.user.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final UserFindPasswordService userFindPasswordService;
    private final JWTService jwtService;

    @PostMapping("/user/sign-up")
    public ResponseEntity<User> signUpUser(@Valid @RequestBody SignUpDto signUpDto) {
        User user = signUpDto.toUser();
        User savedUser = userService.save(user);
        return ResponseEntity.ok(savedUser);
    }

    @PostMapping("/user/sign-in")
    public ResponseEntity<AuthResponse> signInUser(@Valid @RequestBody SignInDto signInDto) {
        final String email = signInDto.getEmail();
        final String password = signInDto.getPassword();


        User user = userService.login(email, password);

        AuthToken authToken = jwtService.createAuthToken(user.getUserId());
        userService.updateRefreshToken(user.getUserId(), authToken.getRefreshToken());

        AuthResponse response = new AuthResponse(authToken);

        return ResponseEntity.ok(response);
    }


    @PostMapping("/user/certification")
    public UserCertificationInput userCertification(@Valid @RequestBody UserCertificationInput userCertificationInput) {
        return userFindPasswordService.certifyUser(userCertificationInput);
    }
    
    @GetMapping("/user/certification")
    public CertificationMailOutput sendCertificationNum() {
        CertificationMailOutput certificationMailOutput = userFindPasswordService.createMail();
        userFindPasswordService.mailSend(certificationMailOutput);
        return certificationMailOutput;
    }
    
    @PatchMapping("/user/password")
    public NewPasswordInput changePassword(@Valid @RequestBody NewPasswordInput newPasswordInput) {
        //토큰으로 유저 인증하고 레포에서 유저 이메일 가져와야함(서비스로 옮길것)
        userFindPasswordService.updatePassword(newPasswordInput);
        return newPasswordInput;
    }
}
