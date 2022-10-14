package com.greedy.semi.member.entity;



import java.sql.Date;

//import java.util.Date;


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
@DynamicInsert /* insert 동작 시 null인 필드를 제외하고 동작한다 */
public class Member {

	@Id
	@Column(name = "MEMBER_ID")
    private String memberId;
	
	@Column(name = "MEMBER_PWD")
    private String memberPwd;
	
	@Column(name = "MEMBER_NAME")
    private String name;
		
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
	
	@Column(name = "REPORT_COUNT")
	private int reportCount;
	
	@Column(name = "ENROLLDATE")
	private Date enrolldate;

   
}
