package com.kael.surf;

import java.util.concurrent.atomic.AtomicInteger;

import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;

public class RetryLimitHashedCredentialsMatcher extends
		HashedCredentialsMatcher {
	private Ehcache passwordRetryCache;

	public RetryLimitHashedCredentialsMatcher() {
		CacheManager manager = CacheManager.newInstance(CacheManager.class.getClassLoader().getResource("ehcache.xml"));
		passwordRetryCache = manager.getCache("passwordFail");
	}

	@Override
	public boolean doCredentialsMatch(AuthenticationToken token,
			AuthenticationInfo info) {
		// TODO Auto-generated method stub
		String username = (String)token.getPrincipal();  
        //retry count + 1  
        Element element = passwordRetryCache.get(username);  
        if(element == null) {  
            element = new Element(username , new AtomicInteger(0));  
            passwordRetryCache.put(element);  
        }  
        AtomicInteger retryCount = (AtomicInteger)element.getObjectValue();  
        if(retryCount.incrementAndGet() > 5) {  
            //if retry count > 5 throw  
            throw new ExcessiveAttemptsException();  
        }  
  
        boolean matches = super.doCredentialsMatch(token, info);  
        if(matches) {  
            //clear retry count  
            passwordRetryCache.remove(username);  
        }  
        return matches;  
	}

}
