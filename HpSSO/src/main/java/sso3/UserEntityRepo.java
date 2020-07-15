package sso3;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserEntityRepo extends CrudRepository<UserEntity, Long>  {

	
	UserEntity findById(long id);
	UserEntity findByEmail(String email);
	
}
