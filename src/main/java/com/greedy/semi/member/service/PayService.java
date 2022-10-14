package com.greedy.semi.member.service;

import javax.transaction.Transactional;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import com.greedy.semi.member.dto.MemberDTO;
import com.greedy.semi.member.dto.PayDTO;
import com.greedy.semi.member.entity.Member;
import com.greedy.semi.member.entity.Pay;
import com.greedy.semi.member.repository.PayRepository;
import com.greedy.semi.trade.dto.TradeDTO;
import com.greedy.semi.trade.entity.Trade;
import com.greedy.semi.trade.repository.TradeRepository;


@Service
@Transactional
public class PayService {
	
	private final PayRepository payRepository;
	private final ModelMapper modelMapper;
	private final TradeRepository tradeRepository;
	
	public PayService(PayRepository payRepository, ModelMapper modelMapper, TradeRepository tradeRepository) {
		this.modelMapper = modelMapper;
		this.payRepository=payRepository;
		this.tradeRepository=tradeRepository;
	}

	public void payAmount(PayDTO pay)
	{
		payRepository.save(modelMapper.map(pay, Pay.class));
	}
	
	public void updatePayStatus(TradeDTO trade)
	{
		Trade payStatus = tradeRepository.findBySellNo(trade.getSellNo());
		payStatus.setPayStatus(trade.getPayStatus());
	}
	
}
