## Redirect requests to Apache, running on port 8000 on localhost
backend apache {
	.host = "127.0.0.1";
	.port = "8000";
}

acl purge {
	"localhost";
	"127.0.0.1";
}

# Respond to incoming requests.
sub vcl_recv {
	# remove ?ver=xxxxx strings from urls so css and js files are cached.
	# Watch out when upgrading WordPress, need to restart Varnish or flush cache.
	set req.url = regsub(req.url, "\?ver=.*$", "");

	# Remove "replytocom" from requests to make caching better.
	set req.url = regsub(req.url, "\?replytocom=.*$", "");

	// Strip cookies for static files:
	if (req.url ~ "\.(jpg|jpeg|gif|png|ico|css|zip|tgz|gz|rar|bz2|pdf|txt|tar|wav|bmp|rtf|js|flv|swf|html|htm)$") {
		unset req.http.Cookie;
		return(lookup);
	}
	// Remove has_js and Google Analytics __* cookies.
	set req.http.Cookie = regsuball(req.http.Cookie, "(^|;\s*)(__[a-z]+|has_js)=[^;]*", "");
	// Remove a ";" prefix, if present.
	set req.http.Cookie = regsub(req.http.Cookie, "^;\s*", "");
	// Remove empty cookies.
	if (req.http.Cookie ~ "^\s*$") {
		unset req.http.Cookie;
	}
	if (req.request == "PURGE") {
		if (!client.ip ~ purge) {
			error 405 "Not allowed.";
		}
		ban("req.url ~ "+req.url+" && req.http.host == "+req.http.host);
		error 200 "Purged.";
	}
	# never cache the admin pages, or the server-status page
	if (req.request == "GET" && (req.url ~ "(wp-admin|bb-admin|server-status)")) {
		return(pipe);
	}
	# don't cache authenticated sessions
	if (req.http.Cookie && req.http.Cookie ~ "(wordpress_|PHPSESSID)") {
		return(pass);
	}
	# don't cache ajax requests
	if(req.http.X-Requested-With == "XMLHttpRequest" || req.url ~ "nocache" || req.url ~ "(control.php|wp-comments-post.php|wp-login.php|bb-login.php|bb-reset-password.php|register.php)") {
		return (pass);
	}
}

sub vcl_hash {
	if (req.http.Cookie) {
		hash_data(req.http.Cookie);
	}
}
## Fetch
sub vcl_fetch {
	## Remove the X-Forwarded-For header if it exists.
	remove req.http.X-Forwarded-For;

	## insert the client IP address as X-Forwarded-For. This is the normal IP address of the user.
	set    req.http.X-Forwarded-For = req.http.rlnclientipaddr;
	## Added security, the "w00tw00t" attacks are pretty annoying so lets block it before it reaches our webserver
	if (req.url ~ "^/w00tw00t") {
		error 403 "Not permitted";
	}
	

	// Strip cookies for static files:
	if (req.url ~ "\.(jpg|jpeg|gif|png|ico|css|zip|tgz|gz|rar|bz2|pdf|txt|tar|wav|bmp|rtf|js|flv|swf|html|htm)$")  {
		unset beresp.http.set-cookie;
	}
	// Varnish determined the object was not cacheable
	if (!beresp.ttl > 0s) {
		set beresp.http.X-Cacheable = "NO:Not Cacheable";
	} elsif(req.http.Cookie ~"(UserID|_session|wp-postpass|wordpress_logged_in|comment_author_)") {
		// You don't wish to cache content for logged in users
		set beresp.http.X-Cacheable = "NO:Got Session";
		return(hit_for_pass);
	}  elsif ( beresp.http.Cache-Control ~ "private") {
		// You are respecting the Cache-Control=private header from the backend
		set beresp.http.X-Cacheable = "NO:Cache-Control=private";
		return(hit_for_pass);
	} elsif ( beresp.ttl < 1s ) {
		// You are extending the lifetime of the object artificially
		set beresp.ttl   = 300s;
		set beresp.grace = 300s;
		set beresp.http.X-Cacheable = "YES:Forced";
	}  else {
		// Varnish determined the object was cacheable
		set beresp.http.X-Cacheable = "YES";
	}

	## Deliver the content
	return(deliver);
}

## Deliver
sub vcl_deliver {
	## We'll be hiding some headers added by Varnish. We want to make sure people are not seeing we're using Varnish.
	## Since we're not caching (yet), why bother telling people we use it?
	remove resp.http.X-Varnish;
	remove resp.http.Via;
	remove resp.http.Age;

	## We'd like to hide the X-Powered-By headers. Nobody has to know we can run PHP and have version xyz of it.
	remove resp.http.X-Powered-By;
}
