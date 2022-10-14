package com.greedy.semi.trade.service;

import java.util.List;
import java.util.stream.Collectors;

import javax.transaction.Transactional;

import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import com.greedy.semi.member.entity.Member;
import com.greedy.semi.trade.dto.Criteria;
import com.greedy.semi.trade.dto.TradeDTO;
import com.greedy.semi.trade.dto.TradeReplyDTO;
import com.greedy.semi.trade.entity.Color;
import com.greedy.semi.trade.entity.Model;
import com.greedy.semi.trade.entity.Region;
import com.greedy.semi.trade.entity.Trade;
import com.greedy.semi.trade.entity.TradeReply;
import com.greedy.semi.trade.repository.TradeReplyRepository;
import com.greedy.semi.trade.repository.TradeRepository;
import com.greedy.semi.trade.repository.TradeRepositoryCustom;

@Service
@Transactional
public class TradeService {
	
	public static final int TRADE_PAGE_SIZE = 6;
	public static final String SORT_BY = "sellNo";
	public static final String SELL_DELETE = "N";
	public static final String PAY_STATUS = "Y";
	
	private final TradeRepository tradeRepository;
	private final TradeReplyRepository tradeReplyRepository;
	private final TradeRepositoryCustom tradeRepositoryCustom;
	private final ModelMapper modelMapper;
	
	public TradeService(TradeRepository tradeRepository, TradeReplyRepository tradeReplyRepository, TradeRepositoryCustom tradeRepositoryCustom, ModelMapper modelMapper) {
		
		this.tradeRepository = tradeRepository;
		this.tradeReplyRepository = tradeReplyRepository;
		this.tradeRepositoryCustom = tradeRepositoryCustom;
		this.modelMapper = modelMapper;
		
	}
	
	public Long registTrade(TradeDTO trade) {
		
		tradeRepository.save(modelMapper.map(trade, Trade.class));
		
		return tradeRepository.getCurrvalSellNoSequence();
	}

	public Page<TradeDTO> selectTradeList(int page, String searchValue) {
		
		Pageable pageable = PageRequest.of(page - 1, TRADE_PAGE_SIZE, Sort.by(SORT_BY).descending());
		
		Page<Trade> tradeList = tradeRepository.findBySearchValue(SELL_DELETE, searchValue, pageable);
		
		if(searchValue != null && !searchValue.isEmpty()) {
			
			tradeList = tradeRepository.findBySearchValue(SELL_DELETE, searchValue, pageable);
			
		} else {
			
			tradeList = tradeRepository.findBySellDelete(SELL_DELETE, pageable);
			
		}
		
		return tradeList.map(trade -> modelMapper.map(trade, TradeDTO.class));
		
	}
	
	public Page<TradeDTO> paidTradeList(int page) {
		
		Pageable pageable = PageRequest.of(page - 1, TRADE_PAGE_SIZE, Sort.by(SORT_BY).descending());
		
		Page<Trade> paidList = tradeRepository.findByPayStatus(SELL_DELETE, PAY_STATUS, pageable);
		
		paidList = tradeRepository.findBySellDeleteAndPayStatus(SELL_DELETE, PAY_STATUS, pageable);
		
		
		return paidList.map(trade -> modelMapper.map(trade, TradeDTO.class));
		
	}

	public Page<TradeDTO> filteringTradeList(Criteria criteria, int page) {
		
		Pageable pageable = PageRequest.of(page - 1, TRADE_PAGE_SIZE, Sort.by(SORT_BY).descending());

		Page<Trade> filteringList = tradeRepositoryCustom.findTradeDynamicQuery(criteria, pageable);
		
		return filteringList.map(trade -> modelMapper.map(trade, TradeDTO.class));
		
	}

	public TradeDTO selectTradeDetail(Long sellNo) {
		
		Trade trade = tradeRepository.findBySellNoAndSellDelete(sellNo, SELL_DELETE);
		trade.setSellCount(trade.getSellCount() + 1);
		
		return modelMapper.map(trade, TradeDTO.class);
		
	}
	
	public void modifyTrade(TradeDTO updateTrade) {

		Trade savedTrade = tradeRepository.findBySellNo(updateTrade.getSellNo());
		savedTrade.setSellNo(updateTrade.getSellNo());
		savedTrade.setSellCarOpt(updateTrade.getSellCarOpt());
		savedTrade.setSellCarDes(updateTrade.getSellCarDes());
		savedTrade.setSellCarName(updateTrade.getSellCarName());
		savedTrade.setSellMileage(updateTrade.getSellMileage());
		savedTrade.setSellPrice(updateTrade.getSellPrice());
		savedTrade.setSellCarYear(updateTrade.getSellCarYear());
		savedTrade.setSellFuel(updateTrade.getSellFuel());
		savedTrade.setSellCountry(updateTrade.getSellCountry());
		savedTrade.setSellTransmission(updateTrade.getSellTransmission());
		savedTrade.setModel(modelMapper.map(updateTrade.getModel(), Model.class));
		savedTrade.setColor(modelMapper.map(updateTrade.getColor(), Color.class));
		savedTrade.setRegion(modelMapper.map(updateTrade.getRegion(), Region.class));
		savedTrade.setSellDisplacement(updateTrade.getSellDisplacement());
		
	}
	
	public void deleteTrade(TradeDTO removeTrade) {

		Trade selectedTrade = tradeRepository.findBySellNo(removeTrade.getSellNo());
		selectedTrade.setSellDelete("Y");
		
	}
	

	public void registTradeReply(TradeReplyDTO registTradeReply) {

		tradeReplyRepository.save(modelMapper.map(registTradeReply, TradeReply.class));
		
		
	}
	
	public List<TradeReplyDTO> loadTradeReply(TradeReplyDTO loadTradeReply) {
		
		List<TradeReply> tradeReplyList
			= tradeReplyRepository.findBySellNoAndReplyDelete(loadTradeReply.getSellNo(), SELL_DELETE);
		
		return tradeReplyList.stream().map(tradeReply -> modelMapper.map(tradeReply, TradeReplyDTO.class)).collect(Collectors.toList());
		
	}
	
	public void removeTradeReply(TradeReplyDTO removeTradeReply) {
		
		TradeReply foundTradeReply = tradeReplyRepository.findByReplyNo(removeTradeReply.getReplyNo());
		foundTradeReply.setReplyDelete("Y");

		
	}

	public void updateTradeReply(TradeReplyDTO updateTradeReply) {
		
		tradeReplyRepository.save(modelMapper.map(updateTradeReply, TradeReply.class));
		
	}

}