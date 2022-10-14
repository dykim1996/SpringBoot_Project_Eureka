package com.greedy.semi.admin.controller;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.data.domain.Page;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.greedy.semi.admin.service.AdminMemberService;
import com.greedy.semi.common.Pagenation;
import com.greedy.semi.common.PagingButtonInfo;
import com.greedy.semi.member.dto.MemberDTO;
import com.greedy.semi.member.service.AuthenticationService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/admin")
public class AdminController {
	
	private final MessageSourceAccessor messageSourceAccessor;
	private final AuthenticationService authenticationService;
	private AdminMemberService adminMemberService;


	public AdminController(MessageSourceAccessor messageSourceAccessor, AdminMemberService memberService, AuthenticationService authenticationService) {
		
		this.authenticationService = authenticationService;
        this.adminMemberService = memberService;
        this.messageSourceAccessor = messageSourceAccessor;
	}	
		
	
	
	@GetMapping("/search")
	public String goSearch(@RequestParam(defaultValue="1") int page, 
			@RequestParam(required=false) String searchValue, Model model) {
		
		log.info("[AdminController] ========================================= ");
		log.info("[AdminController] param page : {}", page);
		log.info("[AdminController] param searchValue : {}", searchValue);
		
		Page<MemberDTO> memberList =  adminMemberService.selectMemberList(page, searchValue);
		PagingButtonInfo paging = Pagenation.getPagingButtonInfo(memberList);
		
		log.info("[MemberController] memberList : {}", memberList);
		log.info("[MemberController] paging : {}", paging);
		
		model.addAttribute("memberList", memberList);
		model.addAttribute("paging", paging);
		if(searchValue != null && !searchValue.isEmpty()) {
			model.addAttribute("searchValue", searchValue);
		}
			log.info("[MemberController] ========================================= ");
			
			return "admin/search";
		}
	
	
	@PostMapping("/delete")
	public String deleteMemberId(String memberId, RedirectAttributes rttr) {
		
		log.info("[AdminController] deleteMemberId ==========================");
		
		log.info("[AdminController] memberId: {} "+ memberId);
		
		adminMemberService.removeMemberId(memberId);
		
		rttr.addFlashAttribute("message", messageSourceAccessor.getMessage("admin.delete"));
		
		
		log.info("[AdminController] deleteMemberId ==========================");
		
		
		return "redirect:/admin/search";
	}
	





	@GetMapping("/warnedmember")
	public String warnedMember(@RequestParam(defaultValue="1") int page, 
			@RequestParam(required=false) String searchValue, Model model) {
		
		log.info("[AdminController] ========================================= ");
		log.info("[AdminController] param page : {}", page);
		log.info("[AdminController] param searchValue : {}", searchValue);
		
		Page<MemberDTO> warnedMember =  adminMemberService.selectWarnedMember(page, searchValue);
		PagingButtonInfo paging = Pagenation.getPagingButtonInfo(warnedMember);
		
		log.info("[MemberController] warnedMemberList : {}", warnedMember);
		log.info("[MemberController] paging : {}", paging);
		
		model.addAttribute("warnedMember", warnedMember);
		model.addAttribute("paging", paging);
	
		if(searchValue != null && !searchValue.isEmpty()) {
			model.addAttribute("searchValue", searchValue);
		}
		
			log.info("[MemberController] =================================");
		
		return "admin/warnedmember";
	}	
	
	

	
	


	@GetMapping("/profit")
	public String goProfit() {
		
		return "admin/profit";
	}	
	
	
	

	
	@GetMapping("/warnedlist")
	public String warnedList() {
		
		return "admin/warnedlist";
	}	
	
		
		

	

	

	
	
	
	
	
	
	
}	