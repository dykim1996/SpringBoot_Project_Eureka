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
@Table(name = "COLOR")
public class Color {
	
	@Id
	@Column(name = "COLOR_CODE")
	private int colorCode;
	
	@Column(name = "COLOR_NAME")
	private String colorName;

}