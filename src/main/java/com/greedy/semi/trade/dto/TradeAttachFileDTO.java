package com.greedy.semi.trade.dto;

import lombok.Data;

@Data
public class TradeAttachFileDTO {
	
	private Long fileNo;
	private Long refSellNo;
	private String fileOrgName;
	private String fileSaveName;
	private String filePath;
	private String fileType;
	private String thumPath;
	private String thumName;

}
