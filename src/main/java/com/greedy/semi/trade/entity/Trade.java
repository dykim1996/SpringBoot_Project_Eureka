package com.greedy.semi.trade.entity;

import java.sql.Date;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

import org.hibernate.annotations.DynamicInsert;

import com.greedy.semi.member.entity.Member;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@ToString
@Entity
@Table(name = "SELL")
@SequenceGenerator(name = "TRADE_SEQ_GENERATOR", sequenceName = "SEQ_SELL_NO", initialValue = 1, allocationSize = 1)
@DynamicInsert
public class Trade {
	
	@Id
	@Column(name = "SELL_NO")
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "TRADE_SEQ_GENERATOR")
	private Long sellNo;
	
	@Column(name = "SELL_CAR_OPT")
	private String sellCarOpt;
	
	@Column(name = "SELL_CAR_DES")
	private String sellCarDes;
	
	@ManyToOne
	@JoinColumn(name = "MEMBER_ID")
	private Member member;
	
	@Column(name = "SELL_CAR_NAME")
	private String sellCarName;
	
	@Column(name = "SELL_MILEAGE")
	private Long sellMileage;
	
	@Column(name = "SELL_PRICE")
	private int sellPrice;
	
	@Column(name = "SELL_CAR_YEAR")
	private int sellCarYear;
	
	@Column(name = "SELL_FUEL")
	private String sellFuel;
	
	@Column(name = "SELL_COUNTRY")
	private String sellCountry;
	
	@Column(name = "SELL_TRANSMISSION")
	private String sellTransmission;
	
	@ManyToOne
	@JoinColumn(name = "MODEL_CODE")
	private Model model;
	
	@ManyToOne
	@JoinColumn(name = "COLOR_CODE")
	private Color color;
	
	@ManyToOne
	@JoinColumn(name = "REGION_CODE")
	private Region region;
	
	@Column(name = "SELL_DELETE")
	private String sellDelete;
	
	@Column(name = "SELL_DATE")
	private Date sellDate;
	
	@Column(name = "SELL_UPDATE")
	private Date sellUpdate;
	
	@Column(name = "SELL_COUNT")
	private Long sellCount;
	
	@Column(name = "SELL_DISPLACEMENT")
	private Long sellDisplacement;
	
	@OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.PERSIST)
	@JoinColumn(name = "REF_SELL_NO")
	private List<TradeAttachFile> attachFileList;
	
	@Column(name = "REPORT_STATUS")
	private String reportStatus;
	
	@Column(name = "PAY_STATUS")
	private String payStatus;

}