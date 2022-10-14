package com.greedy.semi.trade.repository;

import static com.greedy.semi.trade.entity.QTrade.trade;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.support.PageableExecutionUtils;
import org.springframework.stereotype.Repository;

import com.greedy.semi.trade.dto.Criteria;
import com.greedy.semi.trade.entity.Trade;
import com.querydsl.core.BooleanBuilder;
import com.querydsl.jpa.JPQLQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;

@Repository
public class TradeRepositorySupport implements TradeRepositoryCustom {

	private final JPAQueryFactory queryFactory;
	
	public TradeRepositorySupport(JPAQueryFactory queryFactory){
		this.queryFactory = queryFactory;
	}
	
	public Page<Trade> findTradeDynamicQuery(Criteria criteria, Pageable pageable) {
		
		BooleanBuilder builder = new BooleanBuilder();
		
		if(criteria.getModel().getModelCode() != 0){
		    builder.and(trade.model.modelCode.eq(criteria.getModel().getModelCode()));
		}
		
		if(criteria.getSellCarYear() != 0) {
			builder.and(trade.sellCarYear.eq(criteria.getSellCarYear()));
		}
		
		if(criteria.getRegion().getRegionCode() != 0) {
			builder.and(trade.region.regionCode.eq(criteria.getRegion().getRegionCode()));
		}
		
		if(criteria.getSellFuel() != "") {
			builder.and(trade.sellFuel.eq(criteria.getSellFuel()));
		}
		
		if(criteria.getSellCountry() != null) {
			builder.and(trade.sellCountry.eq(criteria.getSellCountry()));
		}
		
		if(criteria.getSellPrice() != 0) {
			
			int startPrice = 0;
			int endPrice = 0;
			
			switch(criteria.getSellPrice()) {
			case 1 : endPrice = 1000;
			case 2 : startPrice = 1000; endPrice = 3000; break;
			case 3 : startPrice = 3000; endPrice = 5000; break;
			case 4 : startPrice = 5000; endPrice = 10000; break;
			case 5 : startPrice = 10000; break;
			}
			
			builder.and(trade.sellPrice.gt(startPrice));
			if(endPrice != 0)
				builder.and(trade.sellPrice.loe(endPrice));
		}
		
		 List<Trade> fetch = queryFactory
				.selectFrom(trade)
				.where(builder)
				.offset(pageable.getOffset())
				.limit(pageable.getPageSize())
				.orderBy(trade.sellNo.desc())
				.fetch();
		
		//count 만 가져오는 쿼리
        JPQLQuery<Trade> count = queryFactory
                .selectFrom(trade)
                .where(builder);
        
        return PageableExecutionUtils.getPage(fetch, pageable, ()-> count.fetchCount());
	}

}
