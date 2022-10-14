package com.greedy.semi.free.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;

import org.hibernate.annotations.DynamicInsert;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "ATTACH_FILE")
@SequenceGenerator(
		name = "FREE_ATTACH_SEQ_GENERATOR", 
		sequenceName = "SEQ_ATTACH_FILE_NO", 
		initialValue = 1, 
		allocationSize = 1
)
@DynamicInsert
public class FreeAttachFile {

	@Id
	@Column(name = "FILE_NO")
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "FREE_ATTACH_SEQ_GENERATOR")
	private Long fileNo;
	
	@Column(name = "FILE_ORGNAME")
	private String fileOrgName;
	
	@Column(name = "FILE_SAVENAME")
	private String fileSaveName;
	
	@Column(name = "FILE_PATH")
	private String filePath;
	
	@Column(name = "FILE_TYPE")
	private String fileType;
	
	@Column(name = "THUM_PATH")
	private String thumPath;
	
	@Column(name = "THUM_NAME")
	private String thumName;

	@Column(name = "REF_FREE_NO")
	private Long refFreeNo;
}
