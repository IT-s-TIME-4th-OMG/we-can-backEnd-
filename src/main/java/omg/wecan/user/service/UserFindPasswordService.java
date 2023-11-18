package omg.wecan.user.service;

import lombok.RequiredArgsConstructor;
import omg.wecan.exception.NoUserWithNameAndEmailException;
import omg.wecan.user.dto.CertificationMailOutput;
import omg.wecan.user.dto.EmailCertificationInput;
import omg.wecan.user.dto.NewPasswordInput;
import omg.wecan.user.dto.UserCertificationInput;
import omg.wecan.user.entity.CertificationMail;
import omg.wecan.user.entity.User;
import omg.wecan.user.repository.CertificationMailRepository;
import omg.wecan.user.repository.UserRepository;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.NoSuchElementException;


@Service
@RequiredArgsConstructor
public class UserFindPasswordService {
    private final UserRepository userRepository;
    private final MailSender mailSender;
    private final CertificationMailRepository certificationMailRepository;
    
    //이메일 주소랑 이름 받아서 검증
    public UserCertificationInput certifyUser(UserCertificationInput userCertificationInput) {
        userRepository.findByEmailAndName(userCertificationInput.getEmail(), userCertificationInput.getName())
                .orElseThrow(() -> new NoUserWithNameAndEmailException("해당 이메일, 이름을 가진 유저가 없음"));
        return userCertificationInput;
    }
    
    // 메일 내용을 생성
    public CertificationMailOutput createMail(EmailCertificationInput emailCertificationInput) {
        String certificationNumber = getCertificationNumber();
        return new CertificationMailOutput(emailCertificationInput.getEmail(), "WECAN! 사용자 인증 이메일 입니다.",
                "안녕하세요. WECAN! 인증 이메일 입니다.\n인증 번호는 " + certificationNumber + " 입니다."
                        + "인증번호 입력란에 인증번호를 입력해주세요!");
    }
    
    //랜덤함수로 인증번호 만들기
    private String getCertificationNumber() {
        char[] certificationNumberArray = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
                'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};
        
        String certificationNumber = "";
        
        // 문자 배열 길이의 값을 랜덤으로 6개를 뽑아 구문을 작성함
        int index;
        for (int i = 0; i < 6; i++) {
            index = (int) (certificationNumberArray.length * Math.random());
            certificationNumber += certificationNumberArray[index];
        }
        return certificationNumber;
    }
    
    // 메일보내기
    public void mailSend(CertificationMailOutput certificationMailOutput) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(certificationMailOutput.getEmail());
        message.setSubject(certificationMailOutput.getTitle());
        message.setText(certificationMailOutput.getMessage());
        message.setFrom("wecan__!@naver.com");
        message.setReplyTo("wecan__!@naver.com");
        System.out.println("message" + message);

        certificationMailRepository.save(new CertificationMail(message.getText()));
        mailSender.send(message);
    }

    public String validateCertificationNum(String certificationNum) {
        CertificationMail certificationMail = certificationMailRepository.findByCertificationNum(certificationNum)
                .orElseThrow(() -> new NoSuchElementException("인증 번호가 틀렸습니다"));
        if (certificationMail.getCreatedAt().isBefore(LocalDateTime.now().plusMinutes(5))) {
            throw new NoSuchElementException("인증 번호가 만료되었습니다");
        }

        return certificationNum;
    }
    
    //비밀번호 변경
    @Transactional
    public void updatePassword(NewPasswordInput newPasswordInput) {
        User user = userRepository.findById(1L).get();
        user.changePassword(newPasswordInput.getNewPassword());
    }
}
