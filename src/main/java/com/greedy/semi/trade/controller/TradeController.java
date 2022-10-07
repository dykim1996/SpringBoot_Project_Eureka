package com.greedy.semi.trade.controller;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.greedy.semi.common.Pagenation;
import com.greedy.semi.common.PagingButtonInfo;
import com.greedy.semi.member.dto.MemberDTO;
import com.greedy.semi.trade.dto.TradeAttachFileDTO;
import com.greedy.semi.trade.dto.TradeDTO;
import com.greedy.semi.trade.dto.TradeReplyDTO;
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
						Thumbnails.of(imageUploadDirectory + "/" + fileSaveName).size(300, 200)
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
		
		trade.setMemberId(member);
		tradeService.registTrade(trade);
		
		rttr.addFlashAttribute("message", messageSourceAccessor.getMessage("trade.regist"));
		
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
		
		
		return "redirect:/trade/list";
		
	}

}
