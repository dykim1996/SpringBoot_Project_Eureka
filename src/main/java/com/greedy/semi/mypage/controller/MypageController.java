package com.greedy.semi.mypage.controller;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.greedy.semi.member.dto.MemberDTO;
import com.greedy.semi.member.service.AuthenticationService;
import com.greedy.semi.member.service.MemberService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/mypage")
public class MypageController {
	
	private final MessageSourceAccessor messageSourceAccessor;
    private final MemberService memberService;
	private final AuthenticationService authenticationService;

	public MypageController(MessageSourceAccessor messageSourceAccessor, MemberService memberService, AuthenticationService authenticationService) {
		
		this.authenticationService = authenticationService;
        this.memberService = memberService;
        this.messageSourceAccessor = messageSourceAccessor;
	}	
	
	@GetMapping("/mypage")
	
	public String myPage() {
		
		return "mypage/mypage";
	}
	
	
	
	@GetMapping("/list")
	public String goList() {
		
		return "mypage/list";
	}

	@GetMapping("/wishlist")
	public String goWishList() {
		
		return "mypage/wishlist";
	}
	
	@GetMapping("/delete")
	public String deleteMember(@AuthenticationPrincipal MemberDTO member, RedirectAttributes rttr) {
		
		  log.info("[MemberController] deleteMember ==========================================================");
	      log.info("[MemberController] member : " + member);
	        
	        memberService.removeMember(member);

	        SecurityContextHolder.clearContext();

	        rttr.addFlashAttribute("message", messageSourceAccessor.getMessage("member.delete"));

	        log.info("[MemberController] deleteMember ==========================================================");

	        return "redirect:/";

	}
	
	@GetMapping("/update")
	public String updateMember() {
		
		return "mypage/update";
	}
	
	  @PostMapping("/update")
	    public String updateMember(@ModelAttribute MemberDTO updateMember,
	    		@RequestParam String zipCode, @RequestParam String address1, @RequestParam String address2,
	    		@AuthenticationPrincipal MemberDTO loginMember,
	    		RedirectAttributes rttr) {
	    	
	    	log.info("[MemberController] modifyMember ==============================");
	    	
	    	String address = zipCode + "$" + address1 + "$" + address2;
	    	updateMember.setAddress(address);
	    	updateMember.setPhone(updateMember.getPhone().replace("-", ""));
	    	
	    	updateMember.setMemberId(loginMember.getMemberId());
	    	
	    	log.info("[MemberController] modifyMember request Member : {}", updateMember);
	    	
	    	memberService.updateMember(updateMember);
	    	
	    	/* 세션에 저장 되어 있는 로그인 회원의 정보를 변경한다. */
	    	Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
	    	SecurityContextHolder.getContext().setAuthentication(createNewAuthentication(authentication, loginMember.getMemberId()));
	    	
	    	rttr.addFlashAttribute("message", messageSourceAccessor.getMessage("member.modify"));
	    	
	    	log.info("[MemberController] modifyMember ==============================");
	    	
	    	return "redirect:/";
	    }

	
	protected Authentication createNewAuthentication(Authentication currentAuth, String memberId) {
	    	
	    UserDetails newPrincipal = authenticationService.loadUserByUsername(memberId);
	    UsernamePasswordAuthenticationToken newAuth = new UsernamePasswordAuthenticationToken(newPrincipal, currentAuth.getCredentials(), newPrincipal.getAuthorities());
	    newAuth.setDetails(currentAuth.getDetails());
	    return newAuth;
	        
	}
	
}