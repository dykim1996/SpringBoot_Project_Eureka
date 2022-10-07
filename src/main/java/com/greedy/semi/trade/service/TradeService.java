package com.greedy.semi.trade.service;

import javax.transaction.Transactional;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import com.greedy.semi.trade.dto.TradeDTO;
import com.greedy.semi.trade.entity.Trade;
import com.greedy.semi.trade.repository.TradeRepository;

@Service
@Transactional
public class TradeService {
	
	public static final int TRADE_PAGE_SIZE = 6;
	public static final String SORT_BY = "sellNo";
	public static final String SELL_DELETE = "N";
	
	private final TradeRepository tradeRepository;
	private final ModelMapper modelMapper;
	
	public TradeService(TradeRepository tradeRepository,ModelMapper modelMapper) {
		
		this.tradeRepository = tradeRepository;
		this.modelMapper = modelMapper;
		
	}
	
	public void registTrade(TradeDTO trade) {
		
		tradeRepository.save(modelMapper.map(trade, Trade.class));
		
	}

}