package com.greedy.semi.member.entity;

import java.sql.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.annotations.DynamicInsert;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "MEMBER")
@DynamicInsert
public class Member {
	
	@Id
	@Column(name = "MEMBER_ID")
	private String memberId;
	
	@Column(name = "MEMBER_PWD")
	private String memberPwd;
	
	@Column(name = "MEMBER_NAME")
	private String memberName;
	
	@Column(name = "BIRTHDAY")
	private Date birthday;
	
	@Column(name = "GENDER")
	private String gender;
	
	@Column(name = "EMAIL")
	private String email;
	
	@Column(name = "PHONE")
	private String phone;
	
	@Column(name = "ADDRESS")
	private String address;
	
	@Column(name = "ACC_SECESSION_YN")
	private String memberStatus;
	
	@Column(name = "MEMBER_ROLE")
	private String memberRole;

}
