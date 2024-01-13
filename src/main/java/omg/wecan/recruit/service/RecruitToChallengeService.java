package omg.wecan.recruit.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import omg.wecan.challenge.entity.Challenge;
import omg.wecan.challenge.entity.UserChallenge;
import omg.wecan.challenge.repository.ChallengeRepository;
import omg.wecan.challenge.repository.UserChallengeRepository;
import omg.wecan.chatting.dto.ChatRoom;
import omg.wecan.chatting.service.ChatService;
import omg.wecan.recruit.entity.Participate;
import omg.wecan.recruit.entity.Recruit;
import omg.wecan.recruit.repository.ParticipateRepository;
import omg.wecan.recruit.repository.RecruitRepository;
import omg.wecan.util.event.MinimumParticipateEvent;
import omg.wecan.util.event.ParticipateFailEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.EventListener;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class RecruitToChallengeService {
    private final RecruitRepository recruitRepository;
    private final ParticipateRepository participateRepository;
    private final ChallengeRepository challengeRepository;
    private final UserChallengeRepository userChallengeRepository;
    private final ChatService chatService;
    private final ApplicationEventPublisher eventPublisher;

    //끝난 모집글 가져와서 피시니 해주고 참여한 애들 챌린지 만들어주고 userchallenge로 보내주고
    @Transactional
    @Scheduled(cron = "30 35 21 * * *")
    public void recruitToChallenge() {
        List<Recruit> finishedRecruits = recruitRepository.findByEndDateIs(LocalDate.now().minusDays(1));
        System.out.println(LocalDate.now().minusDays(1));
        for (Recruit recruit : finishedRecruits) {
            recruit.changeFinished();

            int minPeople = recruit.getMinPeople();
            List<Participate> participatesByRecruit = participateRepository.findByRecruit(recruit);

            if(participatesByRecruit.size() < minPeople){
                eventPublisher.publishEvent(new ParticipateFailEvent(participateRepository.findUserByRecruit(recruit), recruit.getTitle()));
                continue;
            }

            Challenge newChallenge = challengeRepository.save(Challenge.createChallenge(recruit, participatesByRecruit.size()));
            ChatRoom chattingRoom = chatService.createChatRoom(newChallenge.getId());
            newChallenge.setChattingRoomId(chattingRoom.getRoomId());
            challengeRepository.save(newChallenge);

            System.out.println(chattingRoom.getRoomId());
            for (Participate participate : participatesByRecruit) {
                userChallengeRepository.save(UserChallenge.createUserChallenge(participate, newChallenge));
            }
        }
    }
}
