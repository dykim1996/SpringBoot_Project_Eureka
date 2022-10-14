package com.greedy.semi.trade.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.greedy.semi.trade.entity.Trade;

public interface TradeRepository extends JpaRepository<Trade, Long> {
	
	@EntityGraph(attributePaths = {"attachFileList"})
	@Query("SELECT t " + 
			 "FROM Trade t " +
			"WHERE t.sellDelete = :sellDelete " +
			  "AND t.payStatus = 'N'")
	Page<Trade> findBySellDelete(String sellDelete, Pageable pageable);
	
	@EntityGraph(attributePaths = {"attachFileList"})
	@Query("SELECT t " + 
			 "FROM Trade t " +
			"WHERE t.sellDelete = :sellDelete " +
			  "AND t.payStatus = 'N' " +
			  "AND (t.sellCarName LIKE '%' || :searchValue || '%' " +
			   "OR t.sellCarDes LIKE '%' || :searchValue || '%')")
	Page<Trade> findBySearchValue(@Param("sellDelete")String sellDelete, @Param("searchValue")String searchValue, Pageable pageable);
	
	Trade findBySellNoAndSellDelete(Long sellNo, String sellDelete);

	Trade findBySellNo(Long sellNo);

	@EntityGraph(attributePaths = {"attachFileList"})
	@Query(
			"SELECT t " +
			  "FROM Trade t " +
			 "WHERE t.sellDelete = :sellDelete " +
			   "AND t.payStatus = :payStatus")
	Page<Trade> findByPayStatus(@Param("payStatus")String payStatus, @Param("sellDelete")String sellDelete, Pageable pageable);

	@EntityGraph(attributePaths = {"attachFileList"})
	Page<Trade> findBySellDeleteAndPayStatus(String payStatus, String sellDelete, Pageable pageable);

	
	
	
	@Query(value = "SELECT SEQ_SELL_NO.currval FROM dual", nativeQuery = true)
    public Long getCurrvalSellNoSequence();
	
}
