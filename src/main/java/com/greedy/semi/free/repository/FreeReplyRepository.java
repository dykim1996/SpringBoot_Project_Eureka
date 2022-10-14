package com.greedy.semi.free.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.greedy.semi.free.entity.FreeReply;

public interface FreeReplyRepository extends JpaRepository<FreeReply, Long> {

	List<FreeReply> findByFreeNoAndReplyDelete(Long freeNo, String replyDelete);

	FreeReply findByReplyNo(Long replyNo);

	
}

