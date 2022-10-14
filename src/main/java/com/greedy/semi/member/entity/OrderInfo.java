package com.greedy.semi.member.entity;




import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

import org.hibernate.annotations.DynamicInsert;

import com.greedy.semi.trade.entity.Trade;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "ORDER_INFO")
@SequenceGenerator(
		name = "ORDER_INFO_SEQ_GENERATOR",
		sequenceName = "SEQ_ORDER_CODE_NO",
		initialValue = 1, allocationSize = 1)
@DynamicInsert /* insert 동작 시 null인 필드를 제외하고 동작한다 */
public class OrderInfo {

	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "ORDER_INFO_SEQ_GENERATOR")
	@Column(name = "ORDER_CODE")
    private Long orderCode;
	
	@ManyToOne
	@JoinColumn(name = "MEMBER_ID")
    private Member member;
	
	@ManyToOne
	@JoinColumn(name = "PRODUCT_CODE")
    private Product product;
	
	@ManyToOne
	@JoinColumn(name = "SELL_NO")
	private Trade trade;		
	

   
}
