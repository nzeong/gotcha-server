package com.gotcha.server.applicant.service;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.CannedAccessControlList;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.gotcha.server.applicant.domain.Applicant;
import com.gotcha.server.applicant.domain.Favorite;
import com.gotcha.server.applicant.domain.InterviewStatus;
import com.gotcha.server.applicant.domain.Interviewer;
import com.gotcha.server.applicant.domain.Keyword;
import com.gotcha.server.applicant.dto.request.*;
import com.gotcha.server.applicant.dto.response.*;
import com.gotcha.server.applicant.repository.ApplicantRepository;
import com.gotcha.server.applicant.repository.FavoriteRepository;
import com.gotcha.server.applicant.repository.KeywordRepository;
import com.gotcha.server.auth.dto.request.MemberDetails;
import com.gotcha.server.evaluation.dto.response.OneLinerResponse;
import com.gotcha.server.evaluation.repository.OneLinerRepository;
import com.gotcha.server.global.exception.AppException;
import com.gotcha.server.global.exception.ErrorCode;
import com.gotcha.server.mail.service.MailService;
import com.gotcha.server.member.domain.Member;
import com.gotcha.server.member.repository.MemberRepository;
import com.gotcha.server.project.domain.Interview;
import com.gotcha.server.project.repository.InterviewRepository;

import com.gotcha.server.question.domain.CommonQuestion;
import com.gotcha.server.question.repository.CommonQuestionRepository;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.stream.Collectors;

import com.gotcha.server.question.domain.IndividualQuestion;
import com.gotcha.server.question.dto.request.IndividualQuestionRequest;
import com.gotcha.server.question.repository.IndividualQuestionRepository;
import io.micrometer.common.lang.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ApplicantService {
    private final ApplicantRepository applicantRepository;
    private final InterviewRepository interviewRepository;
    private final KeywordRepository keywordRepository;
    private final IndividualQuestionRepository individualQuestionRepository;
    private final OneLinerRepository oneLinerRepository;
    private final MemberRepository memberRepository;
    private final CommonQuestionRepository commonQuestionRepository;
    private final FavoriteRepository favoriteRepository;
    private final AmazonS3 amazonS3;
    private final MailService mailService;

    @Value("${cloud.aws.s3.bucket}")
    private String bucket;

    @Transactional
    public InterviewProceedResponse proceedToInterview(final InterviewProceedRequest request, final MemberDetails details) {
        Applicant applicant = applicantRepository.findByIdWithInterviewAndInterviewers(request.applicantId())
                .orElseThrow(() -> new AppException(ErrorCode.APPLICANT_NOT_FOUNT));
        Interviewer interviewer = applicant.pickInterviewer(details.member());
        interviewer.setPrepared();

        List<Interviewer> interviewers = applicant.getInterviewers();
        long interviewerCount = interviewers.size();
        long preparedInterviewerCount = interviewers.stream().filter(Interviewer::isPrepared).count();
        if (interviewerCount <= preparedInterviewerCount) {
            applicant.moveToNextStatus();
            saveCommonQuestionsTo(applicant);
        }
        return new InterviewProceedResponse(interviewerCount, preparedInterviewerCount);
    }

    public void saveCommonQuestionsTo(final Applicant applicant) {
        List<CommonQuestion> commonQuestions = commonQuestionRepository.findAllByInterview(applicant.getInterview());
        commonQuestions.stream()
                .map(question -> IndividualQuestion.fromCommonQuestion(question, applicant))
                .forEach(question -> applicant.addQuestion(question));

    }

    public List<ApplicantsResponse> listApplicantsByInterview(final Long interviewId, final MemberDetails details) {
        Interview interview = interviewRepository.findById(interviewId)
                .orElseThrow(() -> new AppException(ErrorCode.INTERVIEW_NOT_FOUNT));
        List<Applicant> applicants = applicantRepository.findAllByInterviewWithInterviewer(interview);

        Map<Applicant, List<KeywordResponse>> applicantsWithKeywords = keywordRepository.findAllByApplicants(applicants);
        Map<Applicant, Boolean> favoritesCheck = checkFavorites(applicants, details.member());

        return ApplicantsResponse.generateList(applicantsWithKeywords, favoritesCheck);
    }

    public Map<Applicant, Boolean> checkFavorites(final List<Applicant> applicants, final Member member) {
        List<Applicant> favorites = favoriteRepository.findAllByMemberAndApplicantIn(member, applicants)
                .stream().map(Favorite::getApplicant).toList();
        return applicants.stream()
                .collect(Collectors.toMap(applicant -> applicant, applicant -> favorites.contains(applicant)));
    }

    public ApplicantResponse findApplicantDetailsById(final Long applicantId) {
        Applicant applicant = applicantRepository.findByIdWithInterviewer(applicantId)
                .orElseThrow(() -> new AppException(ErrorCode.APPLICANT_NOT_FOUNT));
        List<Keyword> keywords = keywordRepository.findAllByApplicant(applicant);
        return ApplicantResponse.from(applicant, keywords);
    }

    @Transactional
    public void updateFavorite(final Long applicantId, final MemberDetails details) {
        Member member = details.member();
        Applicant applicant = applicantRepository.findById(applicantId)
                .orElseThrow(() -> new AppException(ErrorCode.APPLICANT_NOT_FOUNT));
        Optional<Favorite> favorite = favoriteRepository.findByApplicantAndMember(applicant, member);

        favorite.ifPresentOrElse(
                favoriteRepository::delete,
                () -> favoriteRepository.save(new Favorite(member, applicant)));
    }

    public List<PassedApplicantsResponse> listPassedApplicantsByInterview(final Long interviewId) {
        Interview interview = interviewRepository.findById(interviewId)
                .orElseThrow(() -> new AppException(ErrorCode.INTERVIEW_NOT_FOUNT));
        List<Applicant> applicants = applicantRepository.findAllPassedApplicants(interview);
        Map<Applicant, List<KeywordResponse>> applicantsWithKeywords = keywordRepository.findAllByApplicants(applicants);
        return PassedApplicantsResponse.generateList(applicantsWithKeywords);
    }

    @Transactional
    public void makeQuestionsPublic(final Long applicantId, final GoQuestionPublicRequest request) {
        Applicant applicant = applicantRepository.findById(applicantId)
                .orElseThrow(() -> new AppException(ErrorCode.APPLICANT_NOT_FOUNT));
        applicant.changeQuestionPublicType(request.agree());
    }

    public void sendPassEmail(final PassEmailSendRequest request) {
        Interview interview = interviewRepository.findById(request.interviewId())
                .orElseThrow(() -> new AppException(ErrorCode.INTERVIEW_NOT_FOUNT));
        String interviewName = interview.getName();
        String positionName = interview.getPosition().getValue();
        String projectName = interview.getProject().getName();

        List<Applicant> applicants = applicantRepository.findAllByInterview(interview);
        for (Applicant applicant : applicants) {
            sendEmailAndChangeStatus(applicant, projectName, interviewName, positionName);
        }
    }

    public void sendEmailAndChangeStatus(
            final Applicant applicant, final String projectName, final String interviewName, final String positionName) {
        mailService.sendEmail(
                applicant.getEmail(),
                String.format("%s님의 %s %s %s 면접 지원 결과 내용입니다.", applicant.getName(), projectName, interviewName, positionName),
                applicant.getOutcome().createPassEmailMessage(applicant.getName(), projectName, interviewName, positionName));
        applicant.moveToNextStatus();
    }

    @Transactional
    public void createApplicant(ApplicantRequest request, Member member) {
        List<Keyword> keywords = createKeywords(request.getKeywords());
        List<IndividualQuestion> questions = createIndividualQuestions(request.getQuestions(), member);
        List<Interviewer> interviewers = createInterviewers(request.getInterviewers());

        Applicant applicant = request.toEntity(findInterviewById(request.getInterviewId()));

        for (Interviewer interviewer : interviewers) {
            applicant.addInterviewer(interviewer);
        }
        for (Keyword keyword : keywords) {
            applicant.addKeyword(keyword);
        }
        for (IndividualQuestion question : questions) {
            applicant.addQuestion(question);
        }

        applicantRepository.save(applicant);
    }

    public Interview findInterviewById(Long interviewId){
        return interviewRepository.findById(interviewId)
                .orElseThrow(() -> new AppException(ErrorCode.INTERVIEW_NOT_FOUNT));
    }

    public void addApplicantFiles(MultipartFile resume, MultipartFile portfolio, Long applicantId) throws IOException {
        String resumeLink = saveUploadFile(resume);
        String portfolioLink = saveUploadFile(portfolio);

        Applicant applicant = applicantRepository.findById(applicantId)
                .orElseThrow(() -> new AppException(ErrorCode.APPLICANT_NOT_FOUNT));
        applicant.updateResumeLink(resumeLink);
        applicant.updatePortfolio(portfolioLink);
    }

    @Transactional
    public String saveUploadFile(@Nullable MultipartFile multipartFile) throws IOException {
        if (multipartFile != null) {
            ObjectMetadata objectMetadata = new ObjectMetadata();
            objectMetadata.setContentType(multipartFile.getContentType());
            objectMetadata.setContentLength(multipartFile.getSize());

            String originalFilename = multipartFile.getOriginalFilename();
            int index = Objects.requireNonNull(originalFilename).lastIndexOf(".");
            String ext = originalFilename.substring(index + 1);

            String storeFileName = UUID.randomUUID() + "." + ext;
            String key = "upload/" + storeFileName;

            try (InputStream inputStream = multipartFile.getInputStream()) {
                amazonS3.putObject(new PutObjectRequest(bucket, key, inputStream, objectMetadata)
                        .withCannedAcl(CannedAccessControlList.PublicRead));
            }

            return amazonS3.getUrl(bucket, key).toString();
        } else {
            return null;
        }
    }

    public List<Keyword> createKeywords(List<KeywordRequest> keywordRequests) {
        return keywordRequests.stream()
                .map(request -> request.toEntity())
                .collect(Collectors.toList());
    }

    public List<IndividualQuestion> createIndividualQuestions(List<IndividualQuestionRequest> questionRequests, Member member) {
        return questionRequests.stream()
                .map(request -> request.toEntity(member, null, null))
                .collect(Collectors.toList());
    }


    public List<Interviewer> createInterviewers(List<InterviewerRequest> interviewerRequests) {
        return interviewerRequests.stream()
                .map(request -> request.toEntity(memberRepository.findById(request.getId()).orElseThrow(() -> new AppException(ErrorCode.MEMBER_NOT_FOUND))))
                .collect(Collectors.toList());
    }

    public List<CompletedApplicantsResponse> getCompletedApplicants(Long interviewId) {
        final Interview interview = interviewRepository.findById(interviewId)
                .orElseThrow(() -> new AppException(ErrorCode.INTERVIEW_NOT_FOUNT));

        final List<Applicant> applicants = resetCompletedApplicants(interview);
        final Map<Applicant, List<KeywordResponse>> keywordMap = keywordRepository.findAllByApplicants(applicants);
        final Map<Applicant, List<OneLinerResponse>> oneLinerMap = oneLinerRepository.getOneLinersForApplicants(applicants);
        return CompletedApplicantsResponse.generateList(applicants, keywordMap, oneLinerMap);
    }

    public List<Applicant> resetCompletedApplicants(Interview interview) {
        final List<Applicant> applicants = applicantRepository.findByInterviewAndInterviewStatus(interview, InterviewStatus.COMPLETION);
        applicants.sort(Collections.reverseOrder()); // 점수 순으로 정렬

        setRanking(applicants);
        setTotalScore(applicants);

        return applicants;
    }

    public void setRanking(List<Applicant> applicants) {
        int currentRank = 1;
        int currentScore = applicants.get(0).getTotalScore();

        for (int i = 0; i < applicants.size(); i++) {
            Applicant applicant = applicants.get(i);

            if (applicant.getTotalScore() < currentScore) {
                currentRank++;
                currentScore = applicant.getTotalScore();
            }

            applicant.updateRanking(currentRank);
        }
    }

    public void setTotalScore(List<Applicant> applicants) {
    }

    public CompletedApplicantDetailsResponse getCompletedApplicantDetails(Long applicantId) {
        final Applicant applicant = applicantRepository.findById(applicantId)
                .orElseThrow(() -> new AppException(ErrorCode.APPLICANT_NOT_FOUNT));

        final List<Keyword> keywords = keywordRepository.findAllByApplicant(applicant);
        final List<OneLinerResponse> oneLiners = oneLinerRepository.getOneLinersForApplicant(applicant);
        return CompletedApplicantDetailsResponse.from(applicant, keywords, oneLiners);
    }
}
