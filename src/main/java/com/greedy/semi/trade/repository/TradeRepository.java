package com.greedy.semi.trade.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.greedy.semi.trade.entity.Trade;

public interface TradeRepository extends JpaRepository<Trade, Long> {
	
	@EntityGraph(attributePaths = {"tradeAttachList"})
	Page<Trade> findBySellDelete(String sellDelete, Pageable pageable);
	
	@EntityGraph(attributePaths = {"tradeAttachList"})
	@Query("SELECT t " + 
			 "FROM Trade t " +
			"WHERE t.sellDelete = :sellDelete " +
			  "AND (t.sellCarName LIKE '%' || :searchValue || '%' " +
			   "OR t.sellCarDes LIKE '%' || :searchValue || '%')")
	Page<Trade> findBySearchValue(@Param("sellDelete")String sellDelete, @Param("searchValue")String searchValue, Pageable pageable);
	
	Trade findBySellNoAndSellDelete(Long sellNo, String sellDelete);
	
}
