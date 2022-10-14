package com.greedy.semi.admin.service;

import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.greedy.semi.admin.repository.AdminMemberRepository;
import com.greedy.semi.member.dto.MemberDTO;
import com.greedy.semi.member.entity.Member;

@Service
@Transactional
public class AdminMemberService {


	private final AdminMemberRepository memberRepository;
	
	private final ModelMapper modelMapper;
	
	public AdminMemberService (AdminMemberRepository memberRepository, ModelMapper modelMapper) {
		this.memberRepository = memberRepository;
		
		this.modelMapper = modelMapper;
	}

	

	private static final int PAGE_SIZE = 7;
	public static final String SORT_BY = "memberId";
	public static final String ACC_SECESSION_YN ="N";
	
	public Page<MemberDTO> selectMemberList(int page, String searchValue) {
		
		Pageable pageable = PageRequest.of(page - 1, PAGE_SIZE, Sort.by(SORT_BY).descending());
		 Page<Member> memberList = null;
		 
		 if(searchValue != null && !searchValue.isEmpty()) {
	 
			
		 }else {
			memberList = memberRepository.findMemberList(pageable);
		 }
		
		return memberList.map(member -> modelMapper.map(member, MemberDTO.class));
	}



	public Page<MemberDTO> selectWarnedMember(int page, String searchValue) {
		
		
		Pageable pageable = PageRequest.of(page -1 , PAGE_SIZE, Sort.by(SORT_BY).descending());
		Page<Member> warnedMember = null;
		
		if(searchValue  != null && !searchValue.isEmpty()) {
			
		}else {
			warnedMember = memberRepository.findMemberList(pageable);
		}
		
		return warnedMember.map(member -> modelMapper.map(member, MemberDTO.class));
	}



	


	public void removeMemberId(String memberId) {
		Member savedMember = memberRepository.findByMemberId(memberId);
		savedMember.setMemberStatus("Y");
	}




	





}
