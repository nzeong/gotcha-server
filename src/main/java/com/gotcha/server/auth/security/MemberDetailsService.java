package com.gotcha.server.auth.security;

import com.gotcha.server.member.domain.Member;
import com.gotcha.server.member.domain.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
        Member member = memberRepository.findBySocialId(id)
                .orElseThrow(() -> new UsernameNotFoundException("존재하지 않는 유저입니다"));
        return new MemberDetails(member);
    }
}
