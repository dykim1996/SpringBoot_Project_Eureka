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
@Table(name = "MODEL")
public class Model {
	
	@Id
	@Column(name = "MODEL_CODE")
	private int modelCode;
	
	@Column(name = "CAR_MODEL")
	private String carModel;

}
