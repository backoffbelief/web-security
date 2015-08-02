package com.kael.surf;


import java.util.Arrays;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

public class AppShiro {
	public static void main(String[] args) {
		
		
		new AppShiro().testFailLogin();
		
		clear();
	}
	
	private static void clear() {
		ThreadContext.unbindSecurityManager();
	}
	
	public void testFailLogin(){
		  for(int i = 1; i <= 5; i++) {
	            try {
	                login("classpath:shiro-retryLimitHashedCredentialsMatcher.ini", "testFailLogin",false, "liu", "234");
	            } catch (Exception e) {/*ignore*/}
	        }
	        login("classpath:shiro-retryLimitHashedCredentialsMatcher.ini", "testFailLogin",false, "liu", "234");
	}
	
	public void testCheckPermission(){
		login("classpath:shiro-permission.ini", "testHasRole", false,"wang", "123");
		System.out.println(Arrays.toString(subject().isPermitted("user:create","user:update","user:delete")));
	}
	
	public void testHasRole(){
		login("classpath:shiro-role.ini", "testHasRole", false,"zhang", "123");
//		System.out.println(Arrays.toString(SecurityUtils.getSubject().hasRoles(Arrays.asList("role1","role2","role3","admin"))));
	    SecurityUtils.getSubject().checkRoles("role1","role3");
	}
	
	private Subject subject(){
		return SecurityUtils.getSubject();
	}

	public void testJdbcRealm(){
		auth0("classpath:shiro-jdbc-realm.ini", "testCustomRealm");
	}
	
	public void testCustomRealm(){
		auth0("classpath:shiro-realm.ini", "testCustomRealm");
	}
	
	public void testBasicIniAuth(){
		auth0("classpath:shiro.ini", "testBasicIniAuth");
	}
	
	private void auth0(String cfg, String methodName) {
		login(cfg, methodName, true,"zhang", "123");
	}
	
	private void login(String cfg, String methodName,boolean isLoginOut,String userName,String password) {
		SecurityUtils.setSecurityManager(new IniSecurityManagerFactory(cfg).getInstance());
		Subject subject = SecurityUtils.getSubject();
		
		UsernamePasswordToken token = new UsernamePasswordToken(userName,password);
		
		subject.login(token);
		
		if(isLoginOut){
			if(subject.isAuthenticated()){
				System.out.println(methodName+"-----authen success!");
			}else {
				System.out.println(methodName+"-----authen failed!");
			}
			
			subject.logout();
		}
	}
}
