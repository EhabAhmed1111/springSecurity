package com.ihab.security.config;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY="c1a7a6461e65ce4e8a362126e3d3b80e16bc400dea0a48a801537347fc071327";

    public String extractUserName(String token) {
        // todo :: these referential op i need to fully understand
//        return extractClaim(token, claims -> claims.getSubject());
        // ::this op is just ref to method within class
        // so with name of class you can get method directly
        return extractClaim(token, Claims::getSubject);
    }

    // here we extract single claim
    // todo i need to fully understand function interface
    // this is lambda function
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        //claims has all claims
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);

    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }


    public String generateToken(
            Map<String, Objects> extraClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                //so HS256 is asymmetric encryption so if you use it you should
                //encrypt the key with asymmetric
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String userName = extractUserName(token);
        //this will validate is the userName in token are same in entity
        //and will check if the token expired
        return (userName.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        //this check if the expiry data is before the current date or not if yes then will return false
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //here we hava all claims
    //but we need to get signing key
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    //here we have signing key
        private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        //here because you use this you should use HS256
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
