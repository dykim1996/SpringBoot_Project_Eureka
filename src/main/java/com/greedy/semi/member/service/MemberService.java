package com.greedy.semi.member.service;

import java.awt.print.Pageable;

import javax.transaction.Transactional;

import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.greedy.semi.member.dto.MemberDTO;
import com.greedy.semi.member.entity.Member;
import com.greedy.semi.member.repository.MemberRepository;


@Service
@Transactional
public class MemberService {
	
	private final MemberRepository memberRepository;
	private final ModelMapper modelMapper;
	private int ACC_SECESSION_YN;
	private Object Sort;
	private Object SORT_BY;
	private Object member;
	
	public MemberService(MemberRepository memberRepository, ModelMapper modelMapper) {
		this.memberRepository = memberRepository;
		this.modelMapper = modelMapper;
	}

	public boolean selectMemberById(String memberId) {
		
		return memberRepository.findByMemberIdAndMemberStatus(memberId, "N").isPresent();
	}

	public void registMember(MemberDTO member) {
		
		memberRepository.save(modelMapper.map(member, Member.class));
	}

	public void updateMember(MemberDTO updateMember) {
		
		Member savedMember = memberRepository.findByMemberId(updateMember.getMemberId());
		savedMember.setName(updateMember.getName());
		savedMember.setPhone(updateMember.getPhone());
		savedMember.setEmail(updateMember.getEmail());
		savedMember.setAddress(updateMember.getAddress());
	}

	/* removeMember 메소드 구현
	   탈퇴 시 즉시 테이블에서 행을 제거하는 것이 아니라 member_status 값을 Y에서 N으로 변경하는 로직이다. */
	public void removeMember(MemberDTO member) {
		
		Member savedMember = memberRepository.findByMemberId(member.getMemberId());
		savedMember.setMemberStatus("N");

	}
	
	public String findIdByNameAndEmail(String name, String email) {
		
		Member member = memberRepository.findIdByNameAndEmail(name, email);
		
		 if (member == null)
	            return null;
	       return member.getMemberId();
	    }


	}
	



