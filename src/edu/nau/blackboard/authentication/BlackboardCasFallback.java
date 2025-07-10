/**
 * This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
    Copyright 2010 Arizona Board of Regents
 */
package edu.nau.blackboard.authentication;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidationException;

import sun.misc.BASE64Decoder;
import blackboard.platform.config.ConfigurationService;
import blackboard.platform.security.authentication.BaseAuthenticationModule;
import blackboard.platform.security.authentication.BbAuthenticationFailedException;
import blackboard.platform.security.authentication.BbCredentialsNotFoundException;
import blackboard.platform.security.authentication.BbSecurityException;

/**
 * 
 * 
 * @author Chris Greenough(Chris.Greenough@nau.edu)
 * @version 1.0
 */
public class BlackboardCasFallback extends BaseAuthenticationModule {
	//Logs are good!
	//private Logger logger = Logger.getLogger("edu.nau.blackboard.authentication.BlackboardCasFallback");
	
	//The BB9.1 login page passes the password back base64 encoded, get it back to plain text
	private BASE64Decoder decoder = new BASE64Decoder();
	
	//What properties to get from authentication.properties
	private static String[] PROP_KEYS = new String[]{
		// General
		"noaccounterror",
		// LDAP
		"ldap.enabled",
		"ldap.base_search",
		"ldap.server_url",
		"ldap.user",
		"ldap.password",
		"ldap.userattrib",
		// CAS
		"cas.enabled",
		"cas.service",
		"cas.url",
		"cas.logout",
		"cas.logout.url"};

	// CAS Server
	private static URL casUrl;
	// Our CAS Service URL
	private static URL casService;
	// Logout URL
	private static URL casRedirectUrl;
	// Use Single Sign Out?
	private static boolean casLogoutCompletely = true;
	// Enable LDAP
	private static boolean ldapEnabled = true;
	// Enable CAS
	private static boolean casEnabled = true;
	// LDAP Server
	private static String ldapServerUrl;
	// Person Base Search
	private static String ldapBaseSearch;
	// Privileged Lookup Account
	private static String ldapUsername;
	// Privileged Lookup Password
	private static String ldapPassword;
	// User Attribute
	private static String ldapUserAttrib;
	// LDAP Context
	// Don't use directly. Must be access in a thread safe, synchronized way.
	private static DirContext _ctx;
	// URL of page to send users that don't have an account
	private static URL noAccountError;
	// Allowed Attributes
	private static String[] allowedAttributes;
	// Which attribute to match groups on
	private static String matchAttribute;
	// Should we filter by LDAP attributes
	private static boolean ldapFilter=false;
	// List of users that always have access
	private static String[] whitelist;
	
	/**
	 * The LDAP directory context object must be access via this synchronized 
	 * method to make it thread safe.
	 * See: http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6516308
	 * @return DirContext
	 */
	private synchronized DirContext getContext(){
		return _ctx;
	}
	
	/**
	 * The LDAP directory context object must be access via this synchronized 
	 * method to make it thread safe.
	 * See: http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6516308
	 * @param ctx
	 */
	private synchronized void setContext(DirContext ctx){
		_ctx=ctx;
	}
	
	/**
	 * Returns the name of this authentication module to the framework
	 * 
	 * @see blackboard.platform.security.authentication.BaseAuthenticationModule#getAuthType()
	 */
	public String getAuthType() {
		return "BlackboardCasFallback";
		
	}
	
	/**
	 * SDK Asks this what properties to return from authentication.properties
	 * 
	 * @see blackboard.platform.security.authentication.BaseAuthenticationModule#getPropKeys()
	 */
	public String[] getPropKeys()
	{
		return PROP_KEYS;
	}

	/**
	 * This is called when the authentication module is initially loaded.
	 * It gets all the static configuration from authentication.properties.
	 * 
	 * @see blackboard.platform.security.authentication.BaseAuthenticationModule#init(blackboard.platform.config.ConfigurationService)
	 */
	public void init(ConfigurationService cfg) {
		_logger.logDebug("Starting BlackboardCasFallback init");
		
		// Get all the configuration info from authentication.properties.
		ldapEnabled = (Boolean)_config.getProperty("ldap.enabled");
		ldapBaseSearch = (String)_config.getProperty("ldap.base_search");
		ldapServerUrl = (String)_config.getProperty("ldap.server_url");

		ldapUsername = (String)_config.getProperty("ldap.user");
		ldapPassword = (String)_config.getProperty("ldap.password");
		ldapUserAttrib = (String)_config.getProperty("ldap.userattrib");
		
		casEnabled = (Boolean)_config.getProperty("cas.enabled");
		casService = (URL)_config.getProperty("cas.service");
		casUrl = (URL)_config.getProperty("cas.url");
		casLogoutCompletely = (Boolean)_config.getProperty("cas.logout");
		casRedirectUrl = (URL)_config.getProperty("cas.logout.url");
		noAccountError = (URL)_config.getProperty("noaccounterror");
		matchAttribute = (String)_config.getProperty("ldap.matchattribute");
		// Connect to LDAP
		if(ldapEnabled)
			initCtx();
		if(ldapEnabled && matchAttribute!=null){
			String strAllowedAttributes = (String)_config.getProperty("ldap.allowedattributes");
			String strWhitelist = (String)_config.getProperty("ldap.whitelist");
			if(strAllowedAttributes!=null){
				allowedAttributes = strAllowedAttributes.split(",");
				for(int i=0;i<allowedAttributes.length;i++){
					allowedAttributes[i] = allowedAttributes[i].trim();
					ldapFilter=true;
				}
			}
			if(ldapFilter && strWhitelist!=null){
				whitelist = strWhitelist.split(",");
				for(int i=0;i<whitelist.length;i++)
					whitelist[i]=whitelist[i].trim();
			}
		}
		
		_logger.logDebug("Finished BlackboardCasFallback init");
	}
	
	/**
	 * Create privileged LDAP bind to find DN's for users
	 * This is called any time a privileged LDAP bind fails. The bind could time out.
	 */
	private void initCtx() {
		Hashtable<String,String> env = new Hashtable<String,String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapServerUrl);
		env.put(Context.SECURITY_AUTHENTICATION,"simple");
		env.put(Context.SECURITY_PRINCIPAL,ldapUsername);
		env.put(Context.SECURITY_CREDENTIALS,ldapPassword);
		try {
			setContext(new InitialDirContext(env));
		} catch (NamingException e) {
			_logger.logFatal("Can not bind to LDAP!");
			_logger.logFatal(e.getMessage());
		}
	}
	
	private void checkFilter(String uid) throws BbAuthenticationFailedException{
		for(String white : whitelist)
			if(white.equalsIgnoreCase(uid)){
				_logger.logDebug("User " + uid + " is on whitelist. Allowing.");
					return;
			}
		if(!ldapFilter){
			_logger.logDebug("No LDAP filter is setup, allowing everyone");
			return;
		}
		
		String[] userGroups = getLdapAttribute(uid,matchAttribute);
		
		for(String userGroup : userGroups){
			for(String allowedAttribute : allowedAttributes){
				if(userGroup.equalsIgnoreCase(allowedAttribute)){
					_logger.logDebug("User " + uid + " has group " + userGroup + " that is on the allow list");
					return;
				}
			}
		}
		_logger.logError("User " + uid + " is not on the whitelist and does not have the proper ldap group. Dening access");
		throw new BbAuthenticationFailedException("You are not authorized to log in.");
	}
	
	/**
	 * This is the main authentication entry point. 
	 * It checks for a ticket in the query string, if on exists it tries to authenticate it via CAS
	 * No ticket, then it tries LDAP.
	 * If that does not work, then fall back to the built in Blackboard RDBMS Authentication
	 * 
	 * @see blackboard.platform.security.authentication.BaseAuthenticationModule#doAuthenticate(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	public String doAuthenticate(HttpServletRequest request, HttpServletResponse response) throws BbSecurityException, BbAuthenticationFailedException, BbCredentialsNotFoundException {
		String ticket = request.getParameter("ticket");
		String service = casService.toString();
		String newLoc = request.getParameter("new_loc");
		if (newLoc != null && newLoc.length() != 0){
				try {
					service = service + "?new_loc=" + java.net.URLEncoder.encode(newLoc,"UTF-8");
				} catch (UnsupportedEncodingException e) {
					throw new BbSecurityException(e.getMessage());
				}
		}
	
		// Try CAS with Ticket.
		if(ticket!=null && casEnabled){
			return doCasAuth(ticket, service);
		}
		
		// Get user name and decode password
		String userId = request.getParameter("user_id");
		String encodedPassword = request.getParameter("encoded_pw");
		String password = null;
		if(encodedPassword != null){
			try {
				password = new String(decoder.decodeBuffer(encodedPassword));
			} catch (IOException e) {
				throw new BbSecurityException(e.getMessage());
			}
		}

		// If we have a user name and password, try LDAP
		if(ldapEnabled && userId !=null && password!=null){
			String ldapUid = doLdapAuth(userId,password);
			if(ldapUid!=null)
				return ldapUid;
		}else{
			if(userId == null)
				_logger.logDebug("userId is null");
			if(password == null)
				_logger.logDebug("encoded_pw is null");
		}
		
		if(ldapFilter && userId != null)
			checkFilter(userId);
		
		// Finally, just fall back to the built in Blackboard authentication
		return super.doAuthenticate(request, response);
	}

	/**
	 * Given a ticket back from CAS and a service URL, check to see if CAS validates it.
	 * 
	 * @param ticket 		CAS Service Ticket
	 * @param service		The URL used to create this CAS ticket
	 * @return 				The UID of the user if CAS authenticates the request, null all other times
	 */
	private String doCasAuth(String ticket, String service) throws BbAuthenticationFailedException {
		Cas20ServiceTicketValidator stv = new Cas20ServiceTicketValidator(casUrl.toString());
		String uid = null;
		try {
			uid = stv.validate(ticket, service).getPrincipal().getName();
			if(ldapFilter)
				checkFilter(uid);
		} catch (TicketValidationException e) {
			_logger.logFatal(e.getMessage());
			throw new BbAuthenticationFailedException(e);
		}

		return uid;
	}
	
	private String[] getLdapAttribute(String userId, String attribute){
		// Do some house keeping.
		// Just return null if LDAP is disabled per authentication.properties
		if(!ldapEnabled){
			_logger.logInfo("doLdapAuth was called, but LDAP is disabled! Not authenticating!");
			return null;
		}
		// Did the context die? We keep it around, but it could die from time to time
		// Try to reconnect.
		if(getContext()==null){
			_logger.logInfo("LDAP Context is NULL and LDAP is enabled. Trying to reconnect.");
			initCtx();
		}
		// If its still dead something else is wrong. Throw errors and return null.
		if(getContext()==null){
			_logger.logFatal("LDAP Context is still NULL. Reconnecting did not succeed. Check logs. doLdapAuth is failed!");
			return null;
		}

		// On to LDAP Authentication.
		// Step one, find the user and get the users DN using a privileged lookup
		Attributes matchAttrs = new BasicAttributes(true);
		matchAttrs.put(new BasicAttribute(ldapUserAttrib,userId));
		// The DN is on the result it self
		String[] retAttrs = {ldapUserAttrib};
		NamingEnumeration<SearchResult> searchResults = null;
		try {
			searchResults = getContext().search(ldapBaseSearch, matchAttrs, retAttrs);
		} catch (NamingException e) {
			_logger.logInfo("Could not search for this user, first time... Will call Init and try again.");
			_logger.logInfo(e.getMessage());
			// Try again, context could have expired due to no activity
			initCtx();
			try {
				searchResults = getContext().search(ldapBaseSearch, matchAttrs, retAttrs);
			} catch (NamingException e1) {
				_logger.logFatal("Could not search for this user, second time... Giveing up.");
				_logger.logFatal(e.getMessage());
				return null;
			}
		}

		// At this point, we should have some search results. 
		if(searchResults==null){
			// If no answers from LDAP, then die
			return null;
		}

		// Get the DN from the search results
		List<String> retAttr = new ArrayList<String>();
		String dn = null;
		try {
			if(searchResults.hasMore()){
				SearchResult sr = (SearchResult)searchResults.next();
				dn = (String)sr.getName();
				Attribute attr = sr.getAttributes().get(attribute);
				if(attr!=null){
					NamingEnumeration e = attr.getAll();
					while(e.hasMore())
						retAttr.add((String)e.next());
				}
			}else{
				_logger.logInfo("Could not find " + ldapUserAttrib + "=" + userId + " in LDAP");
				return null;
			}
		} catch (NamingException e) {
			_logger.logFatal("Could not get attributes for this user");
			_logger.logFatal(e.getMessage());
			return null;
		}
		
		if("dn".equalsIgnoreCase(attribute))
			return new String[]{dn};
		
		return (String[]) retAttr.toArray();
	}
	
	/**
	 * This function tries to bind to LDAP as the user name and password to validate the 
	 * users password. 
	 * This function always returns null if LDAP is disabled or the privileged context is
	 * null. 
	 * 			1. Return null if LDAP is disabled, or the context cannot be created/recreated 
	 * 			2. Lookup the users DN using the privileged LDAP connection
	 * 			3. After the DN is found, bind to LDAP using that DN and password
	 * 			4. If the bind is successful then return the UID
	 * 
	 * @param userId
	 * @param password
	 * @return
	 */
	private String doLdapAuth(String userId, String password) throws BbAuthenticationFailedException{
		if(ldapFilter)
			checkFilter(userId);
		
		String dn = null;
		String[] dns = getLdapAttribute(userId,"dn");
		if(dns!=null && dns.length==1)
			dn=dns[0];
		
		// No DN, No good! Return null
		if(dn==null){
			// No DN from request... Then die
			return null;
		}
		
		// Create new connection to LDAP to bind as this user using
		// the users DN and password
		Hashtable<String,String> env = new Hashtable<String,String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapServerUrl);
		env.put(Context.SECURITY_AUTHENTICATION,"simple");
		env.put(Context.SECURITY_PRINCIPAL,dn + "," + ldapBaseSearch);
		env.put(Context.SECURITY_CREDENTIALS,password);
		DirContext userCtx = null;
		try {
			userCtx = new InitialDirContext(env);
		} catch (Exception e) { // Catching all exceptions, just so something does not slip through
			_logger.logInfo("Cannot bind as user " + userId + " to LDAP using supplied creds");
			_logger.logInfo(e.getMessage());
			return null;
		}finally{
			// Close the user context, leave the private context around for next call
			try {
				if(userCtx!=null){
					userCtx.close();
					userCtx=null;
				}
				env=null;
			} catch (NamingException e) {
				_logger.logFatal("Could not close user context");
				_logger.logFatal(e.getMessage());
			}
		}
		
		// The UID/password is correct. Authenticate the user to Blackboard.
		return userId;
	}

	/** 
	 * Catch the logout event so we can send to CAS single sign out if required.
	 * 
	 * @see blackboard.platform.security.authentication.BaseAuthenticationModule#doLogout(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */

public void doLogout(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws BbSecurityException {
	if ( "logout".equals( request.getParameter( "action" ) ) ){
		try {
		        super.doLogout(request, response);
		        // If no CAS Logout, just return to the login page.
		        if (!casLogoutCompletely)
		                return;
		        // Create CAS logout URL
		        String redirectUrl = casUrl + "/logout";
		        if (casRedirectUrl != null && casRedirectUrl.toString().length() != 0){
		                try {
		                        redirectUrl = redirectUrl + "?url=" + java.net.URLEncoder.encode(casRedirectUrl.toString(),"UTF-8");
		                } catch (UnsupportedEncodingException e) {
		                        _logger.logFatal(e.getMessage());
		                        throw new BbSecurityException(e.getMessage());
		                }
		        }
			response.sendRedirect(redirectUrl);
		} catch (IOException e) {
			_logger.logFatal(e.getMessage());
			throw new BbSecurityException(e.getMessage());
		}
	}
}


	/**
	 * This will either draw the login page, or redirect a user to CAS to get a ticket
	 * 
	 * @see blackboard.platform.security.authentication.BaseAuthenticationModule#requestAuthenticate(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	public void requestAuthenticate(HttpServletRequest request, HttpServletResponse response) throws BbSecurityException
	{
		String errMsg = (String)request.getAttribute("msg");
		//If user doesn't exist. Redirect to a page explaining what's happened.
		if (errMsg != null && errMsg.indexOf("Unable to retrieve user record from the database") != -1) {
		    try {
		        response.sendRedirect(noAccountError.toString());
		    } catch (Exception e) {
		        throw new BbSecurityException(e.getMessage());
		    }
		    return;
		}
		// casRedirect is anything other then true, send to the regular login page.
		String casRedirect = request.getParameter("casRedirect");
		if(!"true".equalsIgnoreCase(casRedirect)){
			super.requestAuthenticate(request, response);
		}else{
			// Create a CAS service URL and send the client to that address.
			// The client will come back with a valid ticket and then be authenticated.
			String serviceUrl=null;
			String newLoc=request.getParameter("new_loc");
			try {
				if(newLoc!=null)
					serviceUrl = "service=" + java.net.URLEncoder.encode(casService.toString() + "?new_loc=" + java.net.URLEncoder.encode(newLoc, "UTF-8"), "UTF-8");
				else
					serviceUrl = "service=" + java.net.URLEncoder.encode(casService.toString(), "UTF-8");
			} catch (UnsupportedEncodingException e) {
				_logger.logFatal(e.getMessage());
			}

			try {
				response.sendRedirect(casUrl + "/login?" + serviceUrl);
			} catch (IOException e) {
				throw new BbSecurityException(e.getMessage());
			}
		}
	}
}
