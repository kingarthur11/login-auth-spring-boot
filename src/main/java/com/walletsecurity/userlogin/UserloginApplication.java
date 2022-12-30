package com.walletsecurity.userlogin;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.Key;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;

@SpringBootApplication
public class UserloginApplication {

	public static void main(String[] args) {

		System.out.println("hellow world");
		SpringApplication.run(UserloginApplication.class, args);
	}

	@Bean
	BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

}

@RestController
class BasicController {

	@Autowired
	AuthenticationManager authenticationManager;
	@Autowired
	JwtUtil jwtUtil;

	@GetMapping("hello")
	public ResponseEntity<String> hello() {
		return ResponseEntity.ok("hello world");
	}

	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody LoginDTO loginDTO) {
		System.out.println("hello world");
		System.out.println(loginDTO.getUsername() + " " + loginDTO.getPassword());
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword());
		authenticationManager.authenticate(token);
		String generateJwtToken = jwtUtil.generate(loginDTO.getUsername());
		return ResponseEntity.ok(generateJwtToken);
	}
}

@Data
class LoginDTO {
	private String username;
	private String password;
}

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
class WebSecurity {

	@Autowired
	UserDetailsService userDetailsService;
	@Autowired
	PasswordEncoder encoder;
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
		return authConfiguration.getAuthenticationManager();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(encoder);
		return authProvider;
	}

	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http
					.csrf().disable()
					.authorizeHttpRequests(authorizeConfig -> {
						authorizeConfig.requestMatchers("/").authenticated();
						authorizeConfig.anyRequest().permitAll();
					})
					.build();
    }

}

@Service
class UserDetailsServiceImpl implements UserDetailsService {
	@Autowired
	PasswordEncoder encoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Map<String, String> map = new HashMap<>();
		map.put("arthur", encoder.encode("arthur1234"));
//		map.put("marthis", encoder.encode("marthins1234"));
		if (map.containsKey(username)) {
			return new User(username, map.get(username), new ArrayList<>());
		}
		throw new UsernameNotFoundException(username);
	}
}

@Service
class JwtUtil {
	private static final int expireInMns = 60 * 1000;
	private final static Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

	public String generate(String username) {
		return Jwts.builder()
				.setSubject(username)
				.setIssuer("backendstory.com")
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + expireInMns))
				.signWith(key)
				.compact();
	}

	public boolean validate(String token) {
		if (getUsername(token) != null && isExpired(token)) {
			return true;
		}
		return false;
	}

	public String getUsername(String token) {
		Claims claims = getClaims(token);
		return claims.getSubject();
	}

	public boolean isExpired(String token) {
		Claims claims = getClaims(token);
		return claims.getExpiration().after(new Date(System.currentTimeMillis()));
	}
	private Claims getClaims(String token) {
		return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
	}
}