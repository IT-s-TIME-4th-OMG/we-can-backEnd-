package omg.wecan.challenge.dto.output;

import lombok.Data;
import omg.wecan.challenge.entity.Challenge;

@Data
public class ChallengeDto {
    private Long id;
    private String title;
    private String challengePeriod;
    private String coverImage;

    public static ChallengeDto fromEntity(Challenge challenge) {
        ChallengeDto challengeDto = new ChallengeDto();
        challengeDto.setId(challenge.getId());
        challengeDto.setTitle(challenge.getTitle());
        challengeDto.setChallengePeriod(challenge.getStartDate()+" ~ "+challenge.getEndDate());
        challengeDto.setCoverImage(challenge.getCoverImageEndpoint());
        return challengeDto;
    }
}
