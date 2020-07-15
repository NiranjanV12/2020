package sso3;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class UserEntity {

	 @Id
	  @GeneratedValue(strategy=GenerationType.AUTO)
	  private Long id;
	 
	 String email;
	 String res_address;
	 String password;
	 String role;

	 
	 
	 
	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getRes_address() {
		return res_address;
	}

	public void setRes_address(String res_address) {
		this.res_address = res_address;
	}

	@Override
	public String toString() {
		return "UserEntity [id=" + id + ", email=" + email + ", res_address=" + res_address + ", password=" + password
				+ ", role=" + role + "]";
	}

	
	 
	
}
