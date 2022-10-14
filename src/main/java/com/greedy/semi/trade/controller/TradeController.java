package com.greedy.semi.trade.controller;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.greedy.semi.common.Pagenation;
import com.greedy.semi.common.PagingButtonInfo;
import com.greedy.semi.member.dto.MemberDTO;
import com.greedy.semi.trade.dto.Criteria;
import com.greedy.semi.trade.dto.TradeAttachFileDTO;
import com.greedy.semi.trade.dto.TradeDTO;
import com.greedy.semi.trade.entity.Trade;
import com.greedy.semi.trade.service.TradeService;

import lombok.extern.slf4j.Slf4j;
import net.coobird.thumbnailator.Thumbnails;

@Slf4j
@Controller
@RequestMapping("/trade")
public class TradeController {
	
	@Value("${image.image-dir}")
	private String IMAGE_DIR;
	
	private final TradeService tradeService;
	private final MessageSourceAccessor messageSourceAccessor;
	
	public TradeController(TradeService tradeService, MessageSourceAccessor messageSourceAccessor) {
		
		this.tradeService = tradeService;
		this.messageSourceAccessor = messageSourceAccessor;
		
	}
	
	@GetMapping("/regist")
	public String goRegister() {
		
		return "trade/tradeRegist";
		
	}
	
	@PostMapping("/regist")
	public String registTrade(TradeDTO trade, List<MultipartFile> attachImage,
			@AuthenticationPrincipal MemberDTO member, RedirectAttributes rttr) {
		
		log.info("========== member : {}", member);
		log.info("[TradeController] =================================================================== ");
		log.info("[TradeController] trade request : {}", trade);
		log.info("[TradeController] attachImage request : {}", attachImage);
		
		String rootLocation = IMAGE_DIR;
		
		String imageUploadDirectory = rootLocation + "/upload/trade/original";
		String thumbnailDirectory = rootLocation + "/upload/trade/thumbnail";
		String accidentDirectory = rootLocation + "/upload/trade/accident";
		
		File directory = new File(imageUploadDirectory);
		File directory2 = new File(thumbnailDirectory);
		File directory3 = new File(accidentDirectory);
		
		log.info("[TradeController] directory request : {}", directory);
		log.info("[TradeController] directory2 request : {}", directory2);
		log.info("[TradeController] directory3 request : {}", directory3);
		
		if(!directory.exists() || !directory2.exists() || !directory3.exists()) {
			
			log.info("[TradeController] 폴더 생성 : {}", directory.mkdirs());
			log.info("[TradeController] 폴더 생성 : {}", directory2.mkdirs());
			log.info("[TradeController] 폴더 생성 : {}", directory3.mkdirs());
			
		}
		
		List<TradeAttachFileDTO> tradeAttachList = new ArrayList<>();
		try {
			for(int i = 0; i < attachImage.size(); i++) {
				
				if(attachImage.get(i).getSize() > 0) {
					
					String fileOrgName = attachImage.get(i).getOriginalFilename();
					
					log.info("[TradeController] fileOrgName : " + fileOrgName);
					
					String ext = fileOrgName.substring(fileOrgName.lastIndexOf("."));
					String fileSaveName = UUID.randomUUID().toString().replace("-", "") + ext;
					
					log.info("[TradeController] fileSaveName : " + fileSaveName);
					
					attachImage.get(i).transferTo(new File(imageUploadDirectory + "/" + fileSaveName));
						
					TradeAttachFileDTO fileInfo = new TradeAttachFileDTO();
					fileInfo.setFileOrgName(fileOrgName);
					fileInfo.setFileSaveName(fileSaveName);
					fileInfo.setFilePath("/upload/trade/original/");
					
					if(i == 0) {
						
						fileInfo.setFileType("ACCIDENT");
						fileInfo.setFilePath("/upload/trade/accident/accident_" + fileSaveName);
						
					} else if(i == 1) {
						
						fileInfo.setFileType("TITLE");
						Thumbnails.of(imageUploadDirectory + "/" + fileSaveName).size(500, 300)
							.toFile(thumbnailDirectory + "/thumbnail_" + fileSaveName);
						fileInfo.setThumPath("/upload/trade/thumbnail/thumbnail_" + fileSaveName);
						
					} else {
						
						fileInfo.setFileType("BODY");
						
					}
					
					tradeAttachList.add(fileInfo);
					
				}
				
			}
		
		log.info("[TradeController] tradeAttachList : {}", tradeAttachList);
		
		trade.setAttachFileList(tradeAttachList);
		
		log.info("[TradeController] trade : {}", trade);
		
		trade.setMember(member);
		
		Long sellNo = tradeService.registTrade(trade);
		
		
		rttr.addFlashAttribute("message", messageSourceAccessor.getMessage("trade.regist"));
		rttr.addAttribute("sellNo", sellNo);
		
		} catch (IllegalStateException | IOException e) {
			
			e.printStackTrace();
			
			for(TradeAttachFileDTO tradeAttach : tradeAttachList) {
				
				File deleteFile = new File(tradeAttach.getFilePath() + "/" + tradeAttach.getFileSaveName());
				deleteFile.delete();
				
				File deleteThumbnail = new File(thumbnailDirectory + "/thumbnail_" + tradeAttach.getFileSaveName());
				deleteThumbnail.delete();
				
			}
			
		}
		
		log.info("[TradeController] =================================================================== ");
		
		
		return "redirect:/member/payment";
		
	}
	
	
	
	
	
	@GetMapping("/list")
	public String selectAllTradeAllList(@RequestParam(defaultValue="1") int page, 
			@RequestParam(required=false) String searchValue, Model model) {
		
		log.info("[TradeController] =================================================================== ");
		log.info("[TradeController] parameter page : {}", page);
		log.info("[TradeController] parameter searchValue : {}", searchValue);
		
		Page<TradeDTO> tradeList = tradeService.selectTradeList(page, searchValue);
		Page<TradeDTO> paidList = tradeService.paidTradeList(page);
		PagingButtonInfo paging = Pagenation.getPagingButtonInfo(tradeList);
		
		log.info("[TradeController] tradeList : {}", tradeList.getContent());
		log.info("[TradeController] paidList : {}", paidList.getContent());
		log.info("[TradeController] paging : {}", paging);
		
		model.addAttribute("tradeList", tradeList);
		model.addAttribute("paidList", paidList);
		model.addAttribute("paging", paging);
		if(searchValue != null && !searchValue.isEmpty()) {
			
			model.addAttribute("searchValue", searchValue);
			
		}
		
		log.info("[TradeController] =================================================================== ");
		
		return "trade/tradeList";
		
	}
	
	@GetMapping("/criteria")
	public String selectFilteringTradeList(Criteria criteria, Model model, @RequestParam(defaultValue="1") int page) {
		log.info("[TradeController] =================================================================== ");
		log.info("[TradeController] criteria : {}", criteria);
		
		Page<TradeDTO> paidList = tradeService.paidTradeList(page);
		Page<TradeDTO> filteringList = tradeService.filteringTradeList(criteria, page);
		PagingButtonInfo paging = Pagenation.getPagingButtonInfo(filteringList);
		
		log.info("[TradeController] paidList : {}", paidList);
		log.info("[TradeController] filteringList : {}", filteringList);
		log.info("[TradeController] paging : {}", paging);
		
		model.addAttribute("paidList", paidList);
		model.addAttribute("tradeList", filteringList);
		model.addAttribute("paging", paging);
		
		return "trade/tradeList";
	} 
	
	@GetMapping("/detail")
	public String selectTradeDetail(Long sellNo, Model model) {
		
		log.info("[TradeController] =================================================================== ");
		log.info("[TradeController] parameter sellNo : {}", sellNo);
		
		TradeDTO trade = tradeService.selectTradeDetail(sellNo);
		
		log.info("[TradeController] trade : {}", trade);
		
		model.addAttribute("sellCarOpt", trade.getSellCarOpt().split(","));
		model.addAttribute("trade", trade);
		
		log.info("[TradeController] =================================================================== ");
		
		return "trade/tradeDetail";
		
	}
	
	@GetMapping("/update")
	public String goUpdate(Long sellNo, Model model) {
		
		log.info("[TradeController] =================================================================== ");
		log.info("[TradeController] parameter sellNo : {}", sellNo);
		
		model.addAttribute("trade", tradeService.selectTradeDetail(sellNo));
		
		log.info("[TradeController] =================================================================== ");
		
		return "trade/tradeUpdate";
		
	}
	
	@PostMapping("/update")
	public String modifyTrade(@ModelAttribute TradeDTO updateTrade, RedirectAttributes rttr) {
		
		log.info("[TradeController] =================================================================== ");
		
		log.info("[TradeController] updateTrade request Trade : {}", updateTrade);
		
		tradeService.modifyTrade(updateTrade);
		
		rttr.addFlashAttribute("message", messageSourceAccessor.getMessage("trade.modify"));
		
		log.info("[TradeController] =================================================================== ");
		
		return "redirect:/trade/list";
		
	}
	
	@GetMapping("/delete")
	public String deleteTrade(TradeDTO trade, RedirectAttributes rttr) {
		
		log.info("[TradeController] =================================================================== ");
		
		tradeService.deleteTrade(trade);
		
		rttr.addFlashAttribute("message", messageSourceAccessor.getMessage("trade.delete"));
		
		log.info("[TradeController] =================================================================== ");
		
		return "redirect:/trade/list";
		
	}
	
	@PostMapping("/registTradeReply")
	public ResponseEntity<String> registReply(@RequestBody TradeReplyDTO registTradeReply,
			@AuthenticationPrincipal MemberDTO member) {
		
		log.info("[TradeController] =================================================================== ");
		log.info("[TradeController] registTradeReply : {}", registTradeReply);
		
		registTradeReply.setMemberId(member);
		
		tradeService.registTradeReply(registTradeReply);
		
		log.info("[TradeController] =================================================================== ");
		
		return ResponseEntity.ok("댓글 등록이 완료되었습니다.");
		
	}
	
	@GetMapping("/loadTradeReply")
	public ResponseEntity<List<TradeReplyDTO>> loadTradeReply(TradeReplyDTO loadTradeReply) {
		
		log.info("[TradeController] =================================================================== ");
		log.info("[TradeController] loadTradeReply : {}", loadTradeReply);
		
		List<TradeReplyDTO> tradeReplyList = tradeService.loadTradeReply(loadTradeReply);
		
		log.info("[TradeController] tradeReplyList : {}", tradeReplyList);
		log.info("[TradeController] =================================================================== ");
		
		return ResponseEntity.ok(tradeReplyList);
	}
	
//	@PostMapping("/updateTradeReply")
//	public ResponseEntity<String> updateTradeReply(@RequestBody TradeReplyDTO updateTradeReply,
//			@AuthenticationPrincipal MemberDTO member) {
//		
//		log.info("[TradeController] =================================================================== ");
//		log.info("[TradeController] updateTradeReply : {}", updateTradeReply);
//		
//		tradeService.updateTradeReply(updateTradeReply);
//		
//		log.info("[TradeController] =================================================================== ");		
//		
//		return ResponseEntity.ok("댓글 수정이 완료되었습니다.");
//	}
//	
	@PostMapping("/removeTradeReply")
	public ResponseEntity<String> removeTradeReply(@RequestBody TradeReplyDTO removeTradeReply) {
		
		log.info("[TradeController] =================================================================== ");
		log.info("[TradeController] removeTradeReply : {}", removeTradeReply);
		
		tradeService.removeTradeReply(removeTradeReply);
		
		log.info("[TradeController] =================================================================== ");
		
		return ResponseEntity.ok("댓글 삭제가 완료되었습니다.");
	}
	
}
