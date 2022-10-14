package com.greedy.semi.trade.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.ContextConfiguration;

import com.greedy.semi.ProjectApplication;
import com.greedy.semi.trade.dto.Criteria;
import com.greedy.semi.trade.dto.ModelDTO;
import com.greedy.semi.trade.dto.RegionDTO;
import com.greedy.semi.trade.entity.Trade;

@SpringBootTest
@ContextConfiguration(classes = { ProjectApplication.class })
public class TradeRepositorySupportTests {
	
	@Autowired
	private TradeRepositorySupport tradeRepositorySupport;
	
	@Test
	public void 카테고리_테스트() {
		
		
		Pageable pagable = PageRequest.of(1, 6);
		Criteria criteria = new Criteria();
		
		ModelDTO model = new ModelDTO();
		model.setModelCode(7);
		
		RegionDTO region = new RegionDTO();
		region.setRegionCode(1);
		
		criteria.setModel(model);
		criteria.setRegion(region);
		criteria.setSellFuel("가솔린");
		criteria.setSellCarYear(2020);
		criteria.setSellCountry("국산");
		criteria.setSellPrice(3);
		
		
		Page<Trade> list = tradeRepositorySupport.findTradeDynamicQuery(criteria, pagable);
		
		list.forEach(trade -> System.out.println(trade));
	}

}
