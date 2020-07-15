package sso3;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class CustomUserDetailsService  extends DefaultOAuth2UserService  implements UserDetailsService

{

@Autowired
UserEntityRepo userEntityRepo;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		System.out.println("loadUserByUsername");

		Map<String, Object> map=new TreeMap<String, Object>();
		map.put("EMPTY", "EMPTY");
		UserEntity userEntity=userEntityRepo.findByEmail(username);
		
		CustomUser customUser=new CustomUser(userEntity.getEmail(),userEntity.getPassword(),  AuthorityUtils.createAuthorityList(userEntity.getRole()),AuthorityUtils.createAuthorityList("EMPTY"),map,userEntity);


return customUser;
	}
	
	
	@Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
		System.out.println("loadUser");

        try {
        	UserEntity userEntity=userEntityRepo.findByEmail(oAuth2User.getAttribute("email"));
			CustomUser customUser= new CustomUser(userEntity.getEmail(),userEntity.getPassword(),AuthorityUtils.createAuthorityList(userEntity.getRole()), oAuth2User.getAuthorities(),oAuth2User.getAttributes(),userEntity);

			return customUser;
        }catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

	
	
	
	
	
	
	
	
	
	
	/* @Override
	    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
	        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

	        try {
	            System.out.println("Service called");
	            
	            }
	        catch (Exception ex) {
	            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
	            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
	        }
			//return new CustomUser("abcd", "String", false, false, false, false, AuthorityUtils.createAuthorityList("ROLE_USER"));
	        return null;
	    }*/


	

}
