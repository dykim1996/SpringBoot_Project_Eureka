package com.greedy.semi.member.service;

import javax.transaction.Transactional;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import com.greedy.semi.member.dto.OrderInfoDTO;
import com.greedy.semi.member.dto.ProductDTO;
import com.greedy.semi.member.entity.OrderInfo;
import com.greedy.semi.member.entity.Product;
import com.greedy.semi.member.repository.OrderInfoRepository;
import com.greedy.semi.member.repository.ProductRepository;


@Service
@Transactional
public class ProductService {
	
	private final ProductRepository productRepository;
	private final ModelMapper modelMapper;
	
	
	public ProductService(ProductRepository productRepository, ModelMapper modelMapper) {
		this.modelMapper = modelMapper;
		this.productRepository=productRepository;
	}

	public ProductDTO findCodeByPayAmt(int payAmt) {

		Product product = productRepository.findCodeByProductPrice(payAmt);
		
		return modelMapper.map(product, ProductDTO.class);
	}

	

	
	
	
	
	
	
	
	
}
