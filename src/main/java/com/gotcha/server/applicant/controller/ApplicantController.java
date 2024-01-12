package com.gotcha.server.applicant.controller;

import com.gotcha.server.applicant.dto.request.ApplicantRequest;
import com.gotcha.server.applicant.dto.request.InterviewProceedRequest;
import com.gotcha.server.applicant.dto.request.PassEmailSendRequest;
import com.gotcha.server.applicant.dto.response.ApplicantResponse;
import com.gotcha.server.applicant.dto.response.ApplicantsResponse;
import com.gotcha.server.applicant.dto.response.InterviewProceedResponse;
import com.gotcha.server.applicant.dto.response.PassedApplicantsResponse;
import com.gotcha.server.applicant.dto.response.TodayInterviewResponse;
import com.gotcha.server.applicant.service.ApplicantService;
import com.gotcha.server.auth.security.MemberDetails;
import java.util.List;

import com.gotcha.server.member.domain.Member;
import com.gotcha.server.member.repository.MemberRepository;
import com.gotcha.server.project.dto.request.ProjectRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/api/applicants")
@RequiredArgsConstructor
public class ApplicantController {
    private final ApplicantService applicantService;
    private final MemberRepository memberRepository;

    @PostMapping("/interview-ready")
    public ResponseEntity<InterviewProceedResponse> proceedToInterview(
            @RequestBody final InterviewProceedRequest request, @AuthenticationPrincipal final MemberDetails details) {
        return ResponseEntity.ok(applicantService.proceedToInterview(request, details));
    }

    @GetMapping("/todays")
    public ResponseEntity<TodayInterviewResponse> countInterview(@AuthenticationPrincipal final MemberDetails details) {
        return ResponseEntity.ok(applicantService.countTodayInterview(details));
    }

    @GetMapping("")
    public ResponseEntity<List<ApplicantsResponse>> findAllApplicantByInterview(@RequestParam(name = "interview-id") final Long interviewId) {
        return ResponseEntity.ok(applicantService.listApplicantsByInterview(interviewId));
    }

    @GetMapping("/{applicant-id}")
    public ResponseEntity<ApplicantResponse> findApplicantDetailsById(@PathVariable(name = "applicant-id") final Long applicantId) {
        return ResponseEntity.ok(applicantService.findApplicantDetailsById(applicantId));
    }

    @GetMapping("/pass")
    public ResponseEntity<List<PassedApplicantsResponse>> findAllPassedApplicantsByInterview(@RequestParam(name = "interview-id") final Long interviewId) {
        return ResponseEntity.ok(applicantService.listPassedApplicantsByInterview(interviewId));
    }

    @PostMapping("/send-email")
    public ResponseEntity<Void> sendPassEmail(@RequestBody final PassEmailSendRequest request) {
        applicantService.sendPassEmail(request);
        return ResponseEntity.ok().build();
    }

    @PostMapping
    public ResponseEntity<String> createApplicant(
            @RequestBody @Valid ApplicantRequest request,
            @AuthenticationPrincipal MemberDetails details) {
        //테스트용 유저 생성
        Member member = Member.builder()
                .email("a@gmail.co")
                .socialId("socialId")
                .name("이름")
                .profileUrl("a.jpg")
                .refreshToken("token")
                .build();
        memberRepository.save(member);
        applicantService.createApplicant(request, member);
//        applicantService.createApplicant(request, details.member());
        return ResponseEntity.status(HttpStatus.CREATED).body("면접 지원자 정보가 입력되었습니다.");
    }
}
