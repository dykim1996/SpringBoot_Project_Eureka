package com.greedy.semi.free.service;

import java.util.List;
import java.util.stream.Collectors;

import javax.transaction.Transactional;

import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import com.greedy.semi.free.dto.FreeDTO;
import com.greedy.semi.free.dto.FreeReplyDTO;
import com.greedy.semi.free.entity.Free;
import com.greedy.semi.free.entity.FreeReply;
import com.greedy.semi.free.repository.FreeReplyRepository;
import com.greedy.semi.free.repository.FreeRepository;


@Service
@Transactional
public class FreeService {
	public static final int TEXT_PAGE_SIZE = 10;
	public static final String SORT_BY = "freeNo";
	public static final String ACTIVE_DELETE = "N";
	
	private final FreeRepository freeRepository;
	private final FreeReplyRepository freeReplyRepository;
	private final ModelMapper modelMapper;
	
	public FreeService(FreeRepository freeRepository, FreeReplyRepository freeReplyRepository, ModelMapper modelMapper) {
		this.freeRepository = freeRepository;
		this.modelMapper = modelMapper;
		this.freeReplyRepository = freeReplyRepository;
	}
	
	public Page<FreeDTO> selectList(int page, String searchValue) {
		
		Pageable pageable = PageRequest.of(page - 1, TEXT_PAGE_SIZE, Sort.by(SORT_BY).descending());
		Page<Free> list = null;
		
		if(searchValue != null && !searchValue.isEmpty()) {
			list = freeRepository.findBySearchValue(ACTIVE_DELETE, searchValue, pageable);
		} else {
			list = freeRepository.findByFreeDelete(ACTIVE_DELETE, pageable);
		}
		
		return list.map(free -> modelMapper.map(free, FreeDTO.class));
	}

	public FreeDTO selectFreeDetail(Long freeNo) {
		
		Free free = freeRepository.findByFreeNoAndFreeDelete(freeNo, ACTIVE_DELETE);
		free.setFreeCount(free.getFreeCount() + 1);
		
		return modelMapper.map(free, FreeDTO.class);
	}

	public void makeFree(FreeDTO free) {

		freeRepository.save(modelMapper.map(free, Free.class));

	}

	public void registReply(FreeReplyDTO registReply) {
		freeReplyRepository.save(modelMapper.map(registReply, FreeReply.class));
		
	}
	
	public List<FreeReplyDTO> loadFreeReply(FreeReplyDTO loadFreeReply) {
		
		List<FreeReply> replyList 
			= freeReplyRepository.findByFreeNoAndReplyDelete(loadFreeReply.getFreeNo(), ACTIVE_DELETE);
		
		return replyList.stream().map(freeReply -> modelMapper.map(freeReply, FreeReplyDTO.class)).collect(Collectors.toList());
	}
	
	public void removeReply(FreeReplyDTO removeReply) {
		
		FreeReply foundReply = freeReplyRepository.findByReplyNo(removeReply.getReplyNo());
		foundReply.setReplyDelete("Y");
		
	}

	public void updateReply(FreeReplyDTO updateReply) {
		FreeReply savedFreeReply = freeReplyRepository.findByReplyNo(updateReply.getReplyNo());
		savedFreeReply.setReplyNo(updateReply.getReplyNo());
		savedFreeReply.setReplyContent(updateReply.getReplyContent());
		
	}
	
	public void deleteFree(FreeDTO removeFree) {
		Free selectedFree = freeRepository.findByFreeNo(removeFree.getFreeNo());
		selectedFree.setFreeDelete("Y");
		
	}

	public void modifyFree(FreeDTO updateFree) {
		Free savedFree = freeRepository.findByFreeNo(updateFree.getFreeNo());
		savedFree.setFreeNo(updateFree.getFreeNo());
		savedFree.setFreeTitle(updateFree.getFreeTitle());
		savedFree.setFreeContent(updateFree.getFreeContent());
	}
	
	public void modifyReply(FreeReplyDTO modifyReply) {
		FreeReply savedFreeReply = freeReplyRepository.findByReplyNo(modifyReply.getReplyNo());
		savedFreeReply.setReplyNo(modifyReply.getReplyNo());
		savedFreeReply.setReplyContent(modifyReply.getReplyContent());
	}


}