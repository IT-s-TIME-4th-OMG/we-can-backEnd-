package omg.wecan.recruit.dto;

import lombok.Data;
import omg.wecan.recruit.Enum.ChallengeType;
import omg.wecan.recruit.Enum.PaymentType;
import omg.wecan.recruit.entity.Recruit;
import omg.wecan.recruit.entity.RecruitComment;
import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

@Data
public class RecruitDetailOutput {
    private Long id;
    private String writer;
    private String charityName;
    private String title;
    private ChallengeType type;
    private LocalDate challengeStartTime;
    private LocalDate challengeEndTime;
    private int minPeople;
    private int participatePeople;
    private String checkDay;
    private PaymentType paymentType;
    private String content;
    private String coverImage;
    private int fine;
    private boolean finished;
    private boolean isParticipate;
    private boolean isHeart;
    private int heartNum;
    private int commentsNum;
    private List<CommentOutput> comments;

    public RecruitDetailOutput(Recruit recruit, int participatePeople, boolean isParticipate,
                               boolean isHeart, List<RecruitComment> recruitComments) {
        this.id = recruit.getId();
        this.writer = recruit.getWriter().getNickName();
        if (recruit.getCharity() == null) {
            this.charityName = recruit.getCharityNotInDb();
        } else {
            this.charityName = recruit.getCharity().getName();
        }
        this.title = recruit.getTitle();
        this.type = recruit.getType();
        this.challengeStartTime = recruit.getEndDate().plusDays(1);
        this.challengeEndTime = recruit.getChallengeEndTime();
        this.minPeople = recruit.getMinPeople();
        this.participatePeople = participatePeople;
        this.checkDay = recruit.getCheckDay();
        this.paymentType = recruit.getPaymentType();
        this.content = recruit.getContent();
        this.coverImage = recruit.getCoverImageEndpoint();

        this.fine = recruit.getFine();
        this.finished = recruit.isFinished();
        this.isHeart = isHeart;
        this.heartNum = recruit.getHeartNum();
        this.isParticipate = isParticipate;
        this.comments = recruitComments.stream().map(CommentOutput::new).collect(Collectors.toList());
        this.commentsNum = comments.size();
    }
}
