package com.greedy.semi.member.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.greedy.semi.member.entity.Member;

public interface MemberRepository extends JpaRepository<Member, String> {
	
	Optional<Member> findByMemberIdAndMemberStatus(String memberId, String memberStatus);

}
