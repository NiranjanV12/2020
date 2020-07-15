package sso3;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class CustomUser extends User implements UserDetails,OidcUser, Serializable {
	
/*	Name: [117116071224349836849],
	Granted Authorities: [[ROLE_USER,
	SCOPE_https://www.googleapis.com/auth/userinfo.email,
	SCOPE_https://www.googleapis.com/auth/userinfo.profile,
	SCOPE_openid]],
	User Attributes: [{at_hash=0QVNL6w_BucL-Ur8A6TpCA,
	sub=117116071224349836849,
	email_verified=true,
	iss=https://accounts.google.com,
	given_name=Niranjan,
	locale=en-GB,
	nonce=1XhXTckTcNWLnQ_4ahL0J_r50qqhdDof31pvwxcLRk0,
	picture=https://lh3.googleusercontent.com/a-/AOh14GgYf0LgEj2n06In0iqS25DcwXSinlC0JAchk0wb=s96-c,
	aud=[1014776119376-rnp4vjlh7cq9kack5ik019n3mi3f2r9h.apps.googleusercontent.com],
	azp=1014776119376-rnp4vjlh7cq9kack5ik019n3mi3f2r9h.apps.googleusercontent.com,
	name=Niranjan Vaity,
	exp=2020-07-09T07:53:39Z,
	family_name=Vaity,
	iat=2020-07-09T06:53:39Z,
	email=niranjanvaity@gmail.com}]*/
	
	private Collection<? extends GrantedAuthority> sso_authorities = null;
			//AuthorityUtils.createAuthorityList("ROLE_USER");
		private Map<String, Object> sso_attributes;
		private String sso_id;
		private String sso_name;
		private String sso_email;
		private String sso_email_verified;
		private UserEntity userEntity;


	public CustomUser(String userName, String password,Collection<? extends GrantedAuthority> authorities, Collection<? extends GrantedAuthority> authorities2,
			Map<String, Object> attributes2,UserEntity userEntity) {
		// TODO Auto-generated constructor stub
		super(userName,password, true, true, true, true, authorities);
		this.sso_attributes=attributes2;
		this.sso_authorities=authorities2;
		this.sso_name=attributes2.get("name")!=null?attributes2.get("name").toString():"";
		this.sso_email=attributes2.get("email")!=null?attributes2.get("email").toString():"";
		this.sso_email_verified=attributes2.get("email_verified")!=null?attributes2.get("email_verified").toString():"";
		this.userEntity=userEntity;
	}

	

	public String getSso_id() {
		return sso_id;
	}



	public void setSso_id(String sso_id) {
		this.sso_id = sso_id;
	}



	public String getSso_name() {
		return sso_name;
	}



	public void setSso_name(String sso_name) {
		this.sso_name = sso_name;
	}



	public String getSso_email() {
		return sso_email;
	}



	public void setSso_email(String sso_email) {
		this.sso_email = sso_email;
	}



	public String getSso_email_verified() {
		return sso_email_verified;
	}



	public void setSso_email_verified(String sso_email_verified) {
		this.sso_email_verified = sso_email_verified;
	}



	public UserEntity getUserEntity() {
		return userEntity;
	}



	public void setUserEntity(UserEntity userEntity) {
		this.userEntity = userEntity;
	}



	public Collection<? extends GrantedAuthority> getSso_authorities() {
		return sso_authorities;
	}



	public void setSso_authorities(Collection<? extends GrantedAuthority> sso_authorities) {
		this.sso_authorities = sso_authorities;
	}



	@Override
	public Map<String, Object> getAttributes() {
		// TODO Auto-generated method stub
		return sso_attributes;
	}


	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return sso_name;
	}


	@Override
	public Map<String, Object> getClaims() {
		// TODO Auto-generated method stub
		return sso_attributes;
	}


	@Override
	public OidcUserInfo getUserInfo() {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public OidcIdToken getIdToken() {
		// TODO Auto-generated method stub
		return null;
	}



	@Override
	public String toString() {
		return "CustomUser [sso_authorities=" + sso_authorities + ", sso_attributes=" + sso_attributes + ", sso_id="
				+ sso_id + ", sso_name=" + sso_name + ", sso_email=" + sso_email + ", sso_email_verified="
				+ sso_email_verified + ", userEntity=" + userEntity + "]";
	}








		
}
