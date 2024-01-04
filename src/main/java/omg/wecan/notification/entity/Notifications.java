package omg.wecan.notification.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import omg.wecan.global.entity.BaseEntity;
import omg.wecan.recruit.entity.Participate;
import omg.wecan.user.entity.User;
import omg.wecan.util.event.BuyItemEvent;
import omg.wecan.util.event.PayChallengeEvent;
import omg.wecan.util.event.RecruitCommentEvent;
import omg.wecan.util.event.SettleChallengeEvent;


@Entity
@NoArgsConstructor
@Getter
public class Notifications extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne(fetch = FetchType.LAZY)
    private User targetUser;
    private String title;
    private String content;
//    private boolean isRead;
    
    public Notifications(RecruitCommentEvent recruitCommentEvent) {
        this.targetUser = recruitCommentEvent.getUser();
        this.title = "누군가 " + recruitCommentEvent.getUser().getNickName() + " 님을 멘션했어요.";
        this.content = recruitCommentEvent.getContent();
    }
    
    public Notifications(Participate participate, String recruitTitle) {
        this.targetUser = participate.getUser();
        this.title = "챌린지 최소 모집 인원이 다 모였어요.";
        this.content ="모집이 끝나면 " + recruitTitle + " 챌린지를 시작할 수 있어요.";
    }
    
    public Notifications(String recruitTitle, Participate participate) {
        this.targetUser = participate.getUser();
        this.title = "내일 " + recruitTitle + " 챌린지가 시작돼요.";
        this.content = participate.getUser().getNickName() + " 님이 챌린지에 성공하기를 응원할게요.";
    }
    
    public Notifications(BuyItemEvent buyItemEvent) {
        this.targetUser = buyItemEvent.getUser();
        this.title = "결제 완료 알림";
        this.content = buyItemEvent.getItem().getName() + " 구매가 완료되었습니다";
    }

    public Notifications(PayChallengeEvent payChallengeEvent) {
        this.targetUser = payChallengeEvent.getUser();
        this.title = "챌린지 입장 비용 결제 알림";
        this.content = payChallengeEvent.getChallenge().getTitle() + "에 대한 결제가 완료되었습니다.";
    }

    public Notifications(SettleChallengeEvent settleChallengeEvent) {
        Long refundCandy = settleChallengeEvent.getRefundCandy();

        this.targetUser = settleChallengeEvent.getUser();
        this.title = "챌린지 정산 알림";

        if(refundCandy != 0L)
            this.content = settleChallengeEvent.getChallenge().getTitle() + "챌린지에 대한 캔디 " + refundCandy + "개가 환급되었습니다.";
        else
            this.content = settleChallengeEvent.getChallenge().getTitle() + "챌린지에 대한 환급 캔디가 없습니다";
    }


}
