package com.greedy.semi.free.repository;


import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import com.greedy.semi.free.entity.Free;

public interface FreeRepository extends JpaRepository<Free, Long> {

	@EntityGraph(attributePaths = {"attachFileList"})
	Page<Free> findByFreeDelete(String freeDelete, Pageable pageable);
	
	@EntityGraph(attributePaths = {"attachFileList"})
	@Query("SELECT b " +
	         "FROM Free b " +
			"WHERE b.freeDelete = :freeDelete " +
			  "AND (b.freeTitle LIKE '%' || :searchValue || '%' " +
			   "OR b.freeContent LIKE '%' || :searchValue || '%')")
	Page<Free> findBySearchValue(@Param("freeDelete") String freeDelete, @Param("searchValue") String searchValue, Pageable pageable);

	Free findByFreeNoAndFreeDelete(Long freeNo, String freeDelete);

	
	Free findByFreeNo(Long freeNo);


}
