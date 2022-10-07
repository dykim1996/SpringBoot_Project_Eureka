package com.greedy.semi.trade.dto;

import java.sql.Date;
import java.util.List;

import com.greedy.semi.member.dto.MemberDTO;

import lombok.Data;

@Data
public class TradeDTO {
	
	private Long sellNo;
	private String sellCarOpt;
	private String sellCarDes;
	private MemberDTO memberId;
	private String sellCarName;
	private Long sellMileage;
	private int sellPrice;
	private int sellCarYear;
	private String sellFuel;
	private String sellCountry;
	private String sellTransmission;
	private ModelDTO model;
	private ColorDTO color;
	private RegionDTO region;
	private String sellDelete;
	private Date sellDate;
	private Date sellUpdate;
	private Long sellCount;
	private Long sellDisplacement;
	private List<TradeAttachFileDTO> attachFileList;

}
