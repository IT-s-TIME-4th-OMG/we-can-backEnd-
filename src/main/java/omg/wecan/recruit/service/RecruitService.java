package omg.wecan.recruit.service;

import lombok.RequiredArgsConstructor;
import omg.wecan.charity.entity.Charity;
import omg.wecan.charity.repository.CharityRepository;
import omg.wecan.recruit.dto.*;
import omg.wecan.recruit.entity.Heart;
import omg.wecan.recruit.entity.Participate;
import omg.wecan.recruit.entity.Recruit;
import omg.wecan.recruit.entity.RecruitComment;
import omg.wecan.recruit.repository.HeartRepository;
import omg.wecan.recruit.repository.ParticipateRepository;
import omg.wecan.recruit.repository.RecruitCommentRepository;
import omg.wecan.recruit.repository.RecruitRepository;
import omg.wecan.user.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RecruitService {
    private final RecruitRepository recruitRepository;
    private final CharityRepository charityRepository;
    private final ParticipateRepository participateRepository;
    private final HeartRepository heartRepository;
    private final RecruitCommentRepository recruitCommentRepository;
    
    public Recruit addRecruit(User loginUser, RecruitInput recruitInput) {
        Optional<Charity> optionalCharityByName = charityRepository.findByName(recruitInput.getCharityName());
        if (optionalCharityByName.isEmpty()) {
            Recruit recruit = Recruit.createRecruitByCharityNotInDb(loginUser, recruitInput);
            recruit = recruitRepository.save(recruit);
            participateRepository.save(Participate.createLeaderParticipate(loginUser, recruit));
            return recruit;
        }
        Recruit recruit = Recruit.createRecruit(loginUser, optionalCharityByName.get(), recruitInput);
        recruit = recruitRepository.save(recruit);
        participateRepository.save(Participate.createLeaderParticipate(loginUser, recruit));
        return recruit;
    }
    
    @Transactional
    public Long updateRecruit(RecruitInput recruitInput) {
        Recruit recruit = recruitRepository.findById(recruitInput.getId()).get();
        Charity charity = charityRepository.findByName(recruitInput.getCharityName()).get();
        recruit.changeRecruit(charity, recruitInput);
        return recruit.getId();
    }
    
    public Long deleteRecruit(Long id) {
        recruitRepository.deleteById(id);
        return id;
    }
    
    public RecruitDetailOutput findRecruitDetail(User loginUser, Long id) {
        Recruit recruit = recruitRepository.findById(id).get();
        return new RecruitDetailOutput(recruit, participateRepository.countByRecruit(recruit),
                participateRepository.existsByUserAndRecruit(loginUser, recruit),
                heartRepository.existsByUserAndRecruit(loginUser, recruit),
                recruitCommentRepository.findByRecruit(recruit));
    }
    //디테일 참여, 댓글 해야함
    
    public List<RecruitOutput> findThreeRecruit(User loginUser) {
        List<Recruit> recruits = recruitRepository.findTop3ByFinishedOrderByHeartNumDescStartDateDesc(false);
        List<RecruitOutput> recruitOutputs = new ArrayList<>();
        if (loginUser != null) {
            for (Recruit recruit : recruits) {
                recruitOutputs.add(new RecruitOutput(recruit, heartRepository.existsByUserAndRecruit(loginUser, recruit)));
            }
            return recruitOutputs;
        }
        for (Recruit recruit : recruits) {
            recruitOutputs.add(new RecruitOutput(recruit, false));
        }
        return recruitOutputs;
    }
    
    public Page<RecruitOutput> findRecruit(User loginUser, RecruitFindCond recruitFindCond, Pageable pageable) {
        //모집글 중에 찜한거 있으면 표시해주기 위해 heart 가져와서 그중에 유저가 찜한 recruit 있는지 확인.
        //유저가 찜한 모집글이 없으면 전부 false로 리턴
        List<Heart> heartsByUser = heartRepository.findAllByUser(loginUser);
        if (heartsByUser.isEmpty()) {
            return recruitRepository.findAllByCond(recruitFindCond, pageable)
                    .map(recruit -> new RecruitOutput(recruit, false));
        }
        //유저가 찜한 모집글이 있으면 그것만 true, 나머지 false로 리턴
        List<RecruitOutput> recruitOutputs = new LinkedList<>();
        Page<Recruit> recruits = recruitRepository.findAllByCond(recruitFindCond, pageable);
        for (Recruit recruit : recruits) {
            recruitOutputs.add(getRecruitOutputByHeart(recruit, heartsByUser));
        }
        return new PageImpl<>(recruitOutputs, pageable, recruits.getTotalElements());
    }
    
    private RecruitOutput getRecruitOutputByHeart(Recruit recruit, List<Heart> heartsByUser) {
        for (Heart heart : heartsByUser) {
            if (heart.getRecruit().equals(recruit)) {
                return new RecruitOutput(recruit, true);
            }
        }
        return new RecruitOutput(recruit, false);
    }
    
    public RecruitComment addRecruitComment(User loginUser, CommentAddInput commentAddInput) {
        Recruit recruit = recruitRepository.findById(commentAddInput.getRecruitId()).get();
        return recruitCommentRepository.save(RecruitComment.createRecruitComment(loginUser, recruit, commentAddInput));
    }
    
    public Long addParticipate(User loginUser, AddParticipateInput addParticipateInput) {
        Recruit recruit = recruitRepository.findById(addParticipateInput.getRecruitId()).get();
        Participate participate = Participate.createParticipate(loginUser, recruit);
        return participateRepository.save(participate).getId();
    }
    
    public Long deleteParticipate(User loginUser, DeleteParticipateAndHeartInput deleteParticipateAndHeartInput) {
        participateRepository.deleteByUserAndRecruit(loginUser, recruitRepository.findById(deleteParticipateAndHeartInput.getRecruitId()).get());
        return deleteParticipateAndHeartInput.getRecruitId();
    }
    
    @Transactional
    public Long addHeart(User loginUser, AddHeartInput addHeartInput) {
        Recruit recruit = recruitRepository.findById(addHeartInput.getRecruitId()).get();
        Heart heart = Heart.createHeart(loginUser, recruit);
        recruit.addHeart();
        return heartRepository.save(heart).getId();
    }
    
    @Transactional
    public Long deleteHeart(User loginUser, DeleteParticipateAndHeartInput deleteParticipateAndHeartInput) {
        Recruit recruit = recruitRepository.findById(deleteParticipateAndHeartInput.getRecruitId()).get();
        Heart heart = heartRepository.findByUserAndRecruit(loginUser, recruit).get();
        recruit.subHeart();
        heartRepository.delete(heart);
        return heart.getId();
    }
}
