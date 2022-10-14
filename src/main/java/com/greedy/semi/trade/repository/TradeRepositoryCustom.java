package com.greedy.semi.trade.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.greedy.semi.trade.dto.Criteria;
import com.greedy.semi.trade.entity.Trade;

public interface TradeRepositoryCustom {

	Page<Trade> findTradeDynamicQuery(Criteria criteria, Pageable pageable);
	
}
