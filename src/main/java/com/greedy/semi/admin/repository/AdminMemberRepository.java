package com.greedy.semi.admin.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.greedy.semi.member.entity.Member;

public interface AdminMemberRepository extends JpaRepository<Member, Long> {

	@Query("SELECT m FROM Member m WHERE m.memberStatus = 'N'")
	Page<Member> findMemberList(Pageable pageable);

	Member findByMemberId(String memberId);

	

	

	
	

}
