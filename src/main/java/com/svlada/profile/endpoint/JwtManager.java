package com.svlada.profile.endpoint;


import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
 
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
 
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.InvalidClaimException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
 
public class JwtManager {
	/**
	 * 1、选择签名的算法
	 * 2、生成签名的密钥
	 * 3、构建Token信息
	 * 4、利用算法和密钥生成Token
	 */
	public static String createToken() {
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
		
		byte[] secretBytes = DatatypeConverter.parseBase64Binary("JWT-TOKEN");
		Key signingKey = new SecretKeySpec(secretBytes, signatureAlgorithm.getJcaName());
		Map<String, Object> claims = new HashMap<String, Object>();
		claims.put("username", "token");
		claims.put("role", "admin");
		JwtBuilder builder = Jwts.builder().setClaims(claims)
				.setId("tokenid")
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis()+10*60*1000))
				.signWith(signatureAlgorithm, signingKey);
		
		return builder.compact();
	}
	
	public static Claims parseToken(String token) {
		return Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary("JWT-TOKEN"))
				.parseClaimsJws(token).getBody();
	}
	
	public static void validateToken(String token) {
		try{
			Claims claims = parseToken(token);
			String username = claims.get("username").toString();
			String role = claims.get("role").toString();
			String tokenid = claims.getId();
			System.out.println("[username]:"+username);
			System.out.println("[role]:"+role);
			System.out.println("[tokenid]:"+tokenid);
		} catch(ExpiredJwtException e) {
			System.out.println("token expired");
		} catch (InvalidClaimException e) {
			System.out.println("token invalid");
		} catch (Exception e) {
			System.out.println("token error");
		}
	}
	
	public static void main(String[] args) {
		validateToken(createToken());
	}
 
}

