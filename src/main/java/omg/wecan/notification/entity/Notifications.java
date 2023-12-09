package omg.wecan.notification.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import omg.wecan.global.entity.BaseEntity;
import omg.wecan.recruit.entity.Participate;
import omg.wecan.user.entity.User;
import omg.wecan.util.event.MinimumParticipateEvent;
import omg.wecan.util.event.RecruitCommentEvent;


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
    
    public Notifications(RecruitCommentEvent recruitCommentEvent) {
        this.targetUser = recruitCommentEvent.getUser();
        this.title = "누군가 " + recruitCommentEvent.getUser().getNickName() + " 님을 멘션했어요.";
        this.content = recruitCommentEvent.getContent();
    }
    
    public Notifications(Participate participate, String recruitTitle) {
        this.targetUser = participate.getUser();
        this.title = "챌린지 최소 모집 인원이 다 모였어요.";
        this.content = recruitTitle + " 챌린지를 시작할 수 있어요.";
    }
}