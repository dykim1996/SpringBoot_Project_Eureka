package com.greedy.semi.member.dto;

import java.util.Date;

import lombok.Data;

@Data
public class PayDTO {
	
	private int payNo;
	private int payAmt;
	private Date payDate;
	private OrderInfoDTO orderInfo;
	
	

}
