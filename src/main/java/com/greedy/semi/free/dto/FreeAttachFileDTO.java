package com.greedy.semi.free.dto;

import lombok.Data;

@Data
public class FreeAttachFileDTO {
	
	private Long fileNo;
	private Long refFreeNo;
	private String fileOrgName;
	private String fileSaveName;
	private String filePath;
	private String fileType;
	private String thumPath;
	private String thumName;

}
