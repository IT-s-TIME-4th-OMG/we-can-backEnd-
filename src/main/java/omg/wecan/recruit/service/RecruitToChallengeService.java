package omg.wecan.recruit.service;

import com.amazonaws.services.kms.model.CloudHsmClusterInUseException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import omg.wecan.challenge.entity.Challenge;
import omg.wecan.challenge.entity.UserChallenge;
import omg.wecan.challenge.repository.ChallengeRepository;
import omg.wecan.challenge.repository.UserChallengeRepository;
import omg.wecan.chatting.entity.ChattingRoom;
import omg.wecan.chatting.entity.ChattingRoomUser;
import omg.wecan.chatting.repository.ChattingRoomRepository;
import omg.wecan.chatting.repository.ChattingRoomUserRepository;
import omg.wecan.recruit.entity.Participate;
import omg.wecan.recruit.entity.Recruit;
import omg.wecan.recruit.repository.ParticipateRepository;
import omg.wecan.recruit.repository.RecruitRepository;
import omg.wecan.util.event.ParticipateFailEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class RecruitToChallengeService {
    private final RecruitRepository recruitRepository;
    private final ParticipateRepository participateRepository;
    private final ChallengeRepository challengeRepository;
    private final UserChallengeRepository userChallengeRepository;
    private final ChattingRoomUserRepository chattingRoomUserRepository;
    private final ChattingRoomRepository chattingRoomRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final ElasticRecruitService elasticRecruitService;

    //끝난 모집글 가져와서 피시니 해주고 참여한 애들 챌린지 만들어주고 userchallenge로 보내주고
    @Transactional
    @Scheduled(cron = "1 0 0 * * *")
    public void recruitToChallenge() {
        List<Recruit> finishedRecruits = recruitRepository.findByEndDateIs(LocalDate.now().minusDays(1));

        for (Recruit recruit : finishedRecruits) {
            recruit.changeFinished();
            elasticRecruitService.deleteRecruit(recruit.getId());

            int minPeople = recruit.getMinPeople();
            List<Participate> participatesByRecruit = participateRepository.findByRecruit(recruit);

            if(participatesByRecruit.size() < minPeople){
                eventPublisher.publishEvent(new ParticipateFailEvent(participateRepository.findUserByRecruit(recruit), recruit.getTitle()));
                continue;
            }

            Challenge newChallenge = challengeRepository.save(Challenge.createChallenge(recruit, participatesByRecruit.size()));
            ChattingRoom chattingRoom = chattingRoomRepository.save(ChattingRoom.create(newChallenge));

            for (Participate participate : participatesByRecruit) {
                userChallengeRepository.save(UserChallenge.createUserChallenge(participate, newChallenge));
                chattingRoomUserRepository.save(ChattingRoomUser.autoCreate(participate, chattingRoom));
            }
        }
    }
}
