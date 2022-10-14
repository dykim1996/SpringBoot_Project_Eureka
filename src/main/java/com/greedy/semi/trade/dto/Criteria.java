package com.greedy.semi.trade.dto;


import lombok.Data;

@Data
public class Criteria {
	
	private ModelDTO model;
	private int sellCarYear;
	private RegionDTO region;
	private String sellFuel;
	private String sellCountry;
	private int sellPrice;

}
