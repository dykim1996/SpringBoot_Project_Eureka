package com.greedy.semi.trade.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "REGION")
public class Region {
	
	@Id
	@Column(name = "REGION_CODE")
	private int regionCode;
	
	@Column(name = "REGION_NAME")
	private String regionName;

}
