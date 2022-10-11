//package com.greedy.semi.admin.controller;
//
//		
//import org.springframework.stereotype.Controller;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.PostMapping;
//
//@Controller
//public class AdminController {
//	
//	@GetMapping(value = {"/admin/search"})
//	public String search() {
//		
//		return "admin/search";
//	}
//	
//	@PostMapping("admin/search")
//	public String redirectAdmin() {
//		
//		return "redirect:/admin/search";
//	}
//			
//}		
package com.greedy.semi.admin.controller;

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


import com.greedy.semi.member.dto.MemberDTO;
import com.greedy.semi.member.service.AuthenticationService;
import com.greedy.semi.member.service.MemberService;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/admin")
public class AdminController {
	
	private final MessageSourceAccessor messageSourceAccessor;
    private final MemberService memberService;
	private final AuthenticationService authenticationService;

	public AdminController(MessageSourceAccessor messageSourceAccessor, MemberService memberService, AuthenticationService authenticationService) {
		
		this.authenticationService = authenticationService;
        this.memberService = memberService;
        this.messageSourceAccessor = messageSourceAccessor;
	}	
	
	@GetMapping("/admin")
	
	public String admin() {
		
		return "admin";
	}
	
	
	
	@GetMapping("/searh")
	public String goSearch() {
		
		return "admin/search";
	}

	@GetMapping("/profit")
	public String goProfit() {
		
		return "admin/profit";
	}	
		

	

	

	
	
	
	
	
	
	
}	
	
	
	
	

