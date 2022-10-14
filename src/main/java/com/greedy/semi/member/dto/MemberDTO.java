package com.greedy.semi.member.dto;

import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Data;

@Data
public class MemberDTO implements UserDetails {

    private String memberId;
    private String memberPwd;
    private String name;
    private Date birthday;
    private String gender;
    private String email;
    private String phone;
    private String address;
    private String memberStatus;
    private String memberRole;
    private int reportCount;
    private Date enrolldate;

	@Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> roles = new HashSet<>();
        roles.add(new SimpleGrantedAuthority(memberRole));
        return roles;
    }

    @Override
    public String getPassword() {
        return memberPwd;
    }

    @Override
    public String getUsername() {
        return memberId;
    }
    
//  
//    public String getMemberId() {
//    	return memberId;
//    }
    
 

    // 계정 만료 여부
    @Override
    public boolean isAccountNonExpired() {
        return true; // 만료되지 않음
    }

    // 계정 잠김 여부
    @Override
    public boolean isAccountNonLocked() {
        return true; // 잠기지 않음
    }

    // 비밀번호 만료 여부
    @Override
    public boolean isCredentialsNonExpired() {
        return true; // 만료되지 않음
    }

    // 계정 활성화 여부
    @Override
    public boolean isEnabled() {
        return true; // 활성화
    }


}
