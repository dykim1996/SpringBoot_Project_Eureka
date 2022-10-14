package com.greedy.semi.member.service;

import javax.transaction.Transactional;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import com.greedy.semi.member.dto.OrderInfoDTO;
import com.greedy.semi.member.entity.OrderInfo;
import com.greedy.semi.member.entity.Pay;
import com.greedy.semi.member.repository.OrderInfoRepository;


@Service
@Transactional
public class OrderInfoService {
	
	private final OrderInfoRepository orderInfoRepository;
	private final ModelMapper modelMapper;
	
	public OrderInfoService(OrderInfoRepository orderInfoRepository, ModelMapper modelMapper) {
		this.modelMapper = modelMapper;
		this.orderInfoRepository=orderInfoRepository;
	}

	public void order(OrderInfoDTO order) {

		orderInfoRepository.save(modelMapper.map(order, OrderInfo.class));

	}

	
	
	
	
	
	
	
	
	
}
