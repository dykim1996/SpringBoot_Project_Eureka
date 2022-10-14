package com.greedy.semi.member.controller;


import java.sql.Date;
import java.util.regex.Pattern;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.greedy.semi.member.dto.MemberDTO;
import com.greedy.semi.member.service.AuthenticationService;
import com.greedy.semi.member.service.MemberService;

import lombok.extern.slf4j.Slf4j;


@Slf4j
@Controller
@RequestMapping("/member")
public class MemberController {

	private final PasswordEncoder passwordEncoder;
    private final MessageSourceAccessor messageSourceAccessor;
    private final MemberService memberService;
    private final AuthenticationService authenticationService;

    public MemberController(MessageSourceAccessor messageSourceAccessor, MemberService memberService, PasswordEncoder passwordEncoder, AuthenticationService authenticationService) {
        this.messageSourceAccessor = messageSourceAccessor;
        this.memberService = memberService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationService = authenticationService;
    }

    @GetMapping("/login")
    public String goLogin() {

        return "member/login";
    }

 
    @PostMapping("/loginfail")
    public String loginFailed(RedirectAttributes rttr) {
    	
    	rttr.addFlashAttribute("message", messageSourceAccessor.getMessage("error.login"));
    	
    	return "redirect:/member/login";
    }
    
    /* 회원 가입 페이지 이동 */
    @GetMapping("/regist")
    public String goRegister() {
    	
    	return "member/regist";
    }
    
    /* 아이디 중복 체크 - 비동기 통신 */
    @PostMapping("/idDupCheck")
    public ResponseEntity<String> checkDuplication(@RequestBody MemberDTO member) {
    	
    	log.info("[MemberController] checkDuplication ========================== ");
    	
    	String result = "사용 가능한 아이디 입니다.";

    	log.info("[MemberController] Request Check ID : {}", member.getMemberId());
    	
    	
    	if(memberService.selectMemberById(member.getMemberId())) {
    		log.info("[MemberController] Already Exist");
    		result = "중복 된 아이디가 존재합니다.";
    	}
		
    	
    	log.info("[MemberController] checkDuplication ========================== ");
    	
    	return ResponseEntity.ok(result);
    }
    
    
    
    
    
    
    /* 회원 가입 */
    @PostMapping("/regist")
    public String registMember(@ModelAttribute MemberDTO member,
    		@RequestParam String zipCode, @RequestParam String address1, @RequestParam String address2,
    		@RequestParam String year, @RequestParam String month, @RequestParam String day, RedirectAttributes rttr) {
    	
    	log.info("[MemberController] registMember ==============================");
    	
    	String address = zipCode + "$" + address1 + "$" + address2;
    	member.setAddress(address);
    	member.setMemberPwd(passwordEncoder.encode(member.getMemberPwd()));
    	member.setPhone(member.getPhone().replace("-", ""));
    	
    	String birthday = year + "-" + month + "-" + day;
    	member.setBirthday(Date.valueOf(birthday));
    	log.info(birthday);
    	log.info(member.getBirthday().toString());
    	
    	log.info("[MemberController] registMember request Member : " + member);
    	
    	memberService.registMember(member);
    	
    	rttr.addFlashAttribute("message", messageSourceAccessor.getMessage("member.regist"));
    	
    	log.info("[MemberController] registMember ==============================");
    	
    	return "redirect:/";
    }
    
    @GetMapping("/searchId")
	public String searchId() {
		return "/member/searchId";
	}
    
	@ResponseBody
	@PostMapping("/searchId")
	public String findIdByName(@RequestParam("name") String name, @RequestParam("email") String email) {
		
		String findId = memberService.findIdByNameAndEmail(name, email);
		
		String resultId = "";
		
		if(findId !=null) {
			
			int id_length = findId.length(); // 아이디의 총 길이
			
			resultId = findId.substring(0, 3);
			
			String answer = "";
			for (int j = 3; j < id_length; j++){
				answer += "*"; 
			}
			
			resultId += answer;
		}
		log.info(findId);
		log.info(resultId);
		return resultId;
	}
	
	   @GetMapping("/payment")
		public String payment() {
			return "/member/payment";
		}
	   
    protected Authentication createNewAuthentication(Authentication currentAuth, String memberId) {
    	
    	UserDetails newPrincipal = authenticationService.loadUserByUsername(memberId);
    	UsernamePasswordAuthenticationToken newAuth = new UsernamePasswordAuthenticationToken(newPrincipal, currentAuth.getCredentials(), newPrincipal.getAuthorities());
    	newAuth.setDetails(currentAuth.getDetails());
        return newAuth;
        
    }
    

}
