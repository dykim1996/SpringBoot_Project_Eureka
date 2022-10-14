package com.greedy.semi.free.controller;

import java.util.List;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.greedy.semi.common.Pagenation;
import com.greedy.semi.common.PagingButtonInfo;
import com.greedy.semi.free.dto.FreeDTO;
import com.greedy.semi.free.dto.FreeReplyDTO;
import com.greedy.semi.free.service.FreeService;
import com.greedy.semi.member.dto.MemberDTO;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Controller
@RequestMapping("/free")
public class FreeController {

	private final FreeService freeService;
	private final MessageSourceAccessor messageSourceAccessor;
	
	public FreeController(FreeService freeService, MessageSourceAccessor messageSourceAccessor) {
		this.freeService = freeService;
		this.messageSourceAccessor = messageSourceAccessor;
	}
	
	@GetMapping("list")
	public String list(@RequestParam(defaultValue="1") int page, 
			@RequestParam(required=false) String searchValue, Model model) {

		Page<FreeDTO> list = freeService.selectList(page, searchValue);
		PagingButtonInfo paging = Pagenation.getPagingButtonInfo(list);
		

		model.addAttribute("list", list);
		model.addAttribute("paging", paging);
		if(searchValue != null && !searchValue.isEmpty()) {
			model.addAttribute("searchValue", searchValue);
		}
	
		return "free/list";
	}
	
	@GetMapping("/detail")
	public String selectFreeDetail(Model model, Long freeNo) {

		FreeDTO free = freeService.selectFreeDetail(freeNo);

		model.addAttribute("free", free);
	
		return "free/freeDetail";
		
	}
	
	
	@GetMapping("/make")
	public String goMake() {
		return "free/make";
	}
	
	@PostMapping("/make")
	public String makeFree(FreeDTO free, @AuthenticationPrincipal MemberDTO member, RedirectAttributes rttr) {

		free.setMemberId(member);
		freeService.makeFree(free);
		
		rttr.addFlashAttribute("message", messageSourceAccessor.getMessage("free.make"));
		
		return "redirect:/free/list";
	}
	
	@PostMapping("/registReply")
	public ResponseEntity<String> registReply(@RequestBody FreeReplyDTO registReply,
			@AuthenticationPrincipal MemberDTO member) {

		log.info("[FreeController] ========================================= ");
		log.info("[FreeController] registReply : {}", registReply);
		
		
		//로그인 유저를 댓글 작성자로 설정
		registReply.setMemberId(member);
		
		// 댓글 입력 후 업데이트 된 해당 게시글의 댓글 목록 조회해서 반환
		freeService.registReply(registReply);

		log.info("[FreeController] ========================================= ");
		
		return ResponseEntity.ok("댓글 등록 완료");
		
	}	
	
	@GetMapping("/loadFreeReply")
	public ResponseEntity<List<FreeReplyDTO>> loadFreeReply(FreeReplyDTO loadFreeReply) {
	
		log.info("[FreeController] ========================================= ");
		log.info("[FreeController] loadReply : {}", loadFreeReply);
		
		List<FreeReplyDTO> replyList = freeService.loadFreeReply(loadFreeReply);
	
		log.info("[FreeController] replyList : {}", replyList);
		log.info("[FreeController] ========================================= ");
		
		return ResponseEntity.ok(replyList);
		
	}
	
	@PostMapping("/removeReply")
	public ResponseEntity<String> removeReply(@RequestBody FreeReplyDTO removeReply, RedirectAttributes rttr) {

		log.info("[FreeController] ========================================= ");
		log.info("[FreeController] loadReply : {}", removeReply);
		
		freeService.removeReply(removeReply);
		
		rttr.addFlashAttribute("message",
		messageSourceAccessor.getMessage("freeReply.remove")); 
		
		log.info("[FreeController] ========================================= ");
		
		return ResponseEntity.ok("댓글 삭제 완료");
	}
	
	@GetMapping("/updateReply")
	public String goUpdateReply(Long replyNo, Model model) {
		
		log.info("[FreeReplyController] =================================================================== ");
		log.info("[FreeReplyController] parameter freeNo : {}", replyNo);
		
		model.addAttribute("free", freeService.selectFreeDetail(replyNo));
		
		log.info("[FreeReplyController] =================================================================== ");
		
		return "free/freeDetail";
		
	}
	
	@PostMapping("/updateReply")
	public String modifyReply(@ModelAttribute FreeReplyDTO updateReply, RedirectAttributes rttr) {
	
		freeService.modifyReply(updateReply);
		
		rttr.addFlashAttribute("message", 
				messageSourceAccessor.getMessage("freeReply.modify"));

		return "redirect:/free/detail?freeNo=" + updateReply.getFreeNo();
	} 
	
	@GetMapping("/update")
	public String goUpdate(Long freeNo, Model model) {
		
		log.info("[FreeController] =================================================================== ");
		log.info("[FreeController] parameter freeNo : {}", freeNo);
		
		model.addAttribute("free", freeService.selectFreeDetail(freeNo));
		
		log.info("[FreeController] =================================================================== ");
		
		return "free/freeUpdate";
		
	}
	
	@PostMapping("/update")
	public String modifyFree(@ModelAttribute FreeDTO updateFree, RedirectAttributes rttr) {
		
		log.info("[FreeController] =================================================================== ");
		
		log.info("[FreeController] updateFree request Free : {}", updateFree);
		
		freeService.modifyFree(updateFree);
		
		rttr.addFlashAttribute("message", 
				messageSourceAccessor.getMessage("free.modify"));
		
		log.info("[FreeController] =================================================================== ");

		return "redirect:/free/detail?freeNo=" + updateFree.getFreeNo();
	} 
	
	@GetMapping("/delete")
	public String deleteFree(FreeDTO free, RedirectAttributes rttr) {

		freeService.deleteFree(free);
	
		rttr.addFlashAttribute("message", messageSourceAccessor.getMessage("free.delete"));
		
		return "redirect:/free/list";
	}
}
