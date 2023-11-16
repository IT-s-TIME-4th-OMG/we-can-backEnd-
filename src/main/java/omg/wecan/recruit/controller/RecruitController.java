package omg.wecan.recruit.controller;

import lombok.RequiredArgsConstructor;
import omg.wecan.recruit.Enum.ChallengeType;
import omg.wecan.recruit.dto.*;
import omg.wecan.recruit.entity.Heart;
import omg.wecan.recruit.entity.Participate;
import omg.wecan.recruit.entity.Recruit;
import omg.wecan.recruit.entity.RecruitComment;
import omg.wecan.recruit.service.RecruitService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class RecruitController {
    private final RecruitService recruitService;
    
    @PostMapping("/recruit")
    public Recruit recruitAdd(@RequestBody RecruitInput recruitInput) {
        //토큰으로 유저 인증하고 레포에서 유저 가져와야함
        return recruitService.addRecruit(recruitInput);
    }
    
    @PatchMapping("/recruit")
    public Recruit recruitUpdate(@RequestBody RecruitInput recruitInput) {
        return recruitService.updateRecruit(recruitInput);
    }
    
    @DeleteMapping("/recruit/{id}")
    public Long recruitDelete(@PathVariable Long id) {
        return recruitService.deleteRecruit(id);
    }
    
    @GetMapping("/recruit/{id}")
    public RecruitDetailOutput recruitDetails(@PathVariable Long id) {
        return recruitService.findRecruitDetail(id);
    }
    
    @GetMapping("/recruits/home")
    public List<RecruitOutput> recruitFindThree() {
        return recruitService.findThreeRecruit();
    }
    
    @GetMapping("/recruits")
    public Page<RecruitOutput> recruitFind(@ModelAttribute RecruitFindCond recruitFindCond, @PageableDefault(size = 4)Pageable pageable) {
        return recruitService.findRecruit(recruitFindCond, pageable);
    }

    @PostMapping("/recruit/comment")
    public RecruitComment recruitCommentAdd(@RequestBody CommentAddInput commentAddInput) {
        return recruitService.addRecruitComment(commentAddInput);
    }
    
    @PostMapping("/recruit/participation")
    public Participate participateAdd(@RequestBody AddParticipateInput addParticipateInput) {
        return recruitService.addParticipate(addParticipateInput);
    }

    @DeleteMapping("/recruit/participation")
    public Long participateDelete(@RequestBody Long  participateId) {
        return recruitService.deleteParticipate(participateId);
    }
    
    @PostMapping("/recruit/heart")
    public Heart heartAdd(@RequestBody AddHeartInput addHeartInput) {
        return recruitService.addHeart(addHeartInput);
    }

    @DeleteMapping("/recruit/heart")
    public Long heartDelete(@RequestBody Long heartId) {
        return recruitService.deleteHeart(heartId);
    }
}