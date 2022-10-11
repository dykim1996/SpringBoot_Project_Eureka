package com.greedy.semi.member.repository;

import java.awt.print.Pageable;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.JpaRepository;

import com.greedy.semi.member.entity.Member;

public interface MemberRepository extends JpaRepository<Member, Integer> {
	
	Optional<Member> findByMemberIdAndMemberStatus(String memberId, String memberStatus);

	Member findIdByNameAndEmail(String name, String email);
	
	Member findByMemberId(String memberId);






}
