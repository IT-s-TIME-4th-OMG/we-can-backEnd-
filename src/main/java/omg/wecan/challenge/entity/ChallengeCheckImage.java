package omg.wecan.challenge.entity;
import jakarta.persistence.*;
import lombok.*;
import omg.wecan.user.entity.User;

import java.util.UUID;

@Entity
@AllArgsConstructor
@NoArgsConstructor()
@Data
public class ChallengeCheckImage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "image_id")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "check_id")
    private ChallengeCheck challengeCheck;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    private String originName;

    private String storedName;

    private String imageUrl;

    public ChallengeCheckImage(ChallengeCheck challengeCheck, String originName) {
        this.user = challengeCheck.getUser();
        this.challengeCheck = challengeCheck;
        this.originName = originName;
        this.storedName = getFileName(originName);
        this.imageUrl = "";
    }

    public ChallengeCheckImage imageSave(ChallengeCheck challengeCheck, String imageUrl) {
        ChallengeCheckImage challengeCheckImage = new ChallengeCheckImage();
        challengeCheckImage.setUser(challengeCheck.getUser());
        challengeCheckImage.setChallengeCheck(challengeCheck);
        challengeCheckImage.setImageUrl(imageUrl);
        return challengeCheckImage;
    }

    // 이미지 파일의 확장자 추출 메소드
    public String extractExtension(String originName) {
        int index = originName.lastIndexOf('.');

        return originName.substring(index, originName.length());
    }

    public String getFileName(String originName) {
        return UUID.randomUUID() + "." + extractExtension(originName);
    }
}