<?php
defined('_JEXEC') or die;

class JHackGuard_Input_Filters {
public $build_time = 1392226272;

public $log_level = 0;

public function __construct()
{
$this->log_level = JComponentHelper::getParams('com_jhackguard')->get('log_level',1);
}

/* Goes through each method of this class and executes it
** ignores run and add_log methods */

public function run(){
$methods = get_class_methods('JHackGuard_Input_Filters');
ob_start();
foreach($methods as $m){
    if(!in_array($m,array('run','add_log','__construct')))
    {
        $this->$m();
    }
}
ob_end_clean();
}

public function add_log($message, $severity)
    {
        /* Compare the system log level and the log request level*/
        $log_this = FALSE;
        switch($severity)
        {
            case 'debug':
                if($this->log_level == 2)
                    $log_this = TRUE;
                    break;
            case 'standard':
                if($this->log_level > 0)
                    $log_this = TRUE;
                    break;
        } 
        //Shall we log?
        if(!$log_this)
        {
            unset($log_this);
            return FALSE;
        }
        unset($log_this);
        //We shall log.
        $log_entry = new stdClass();
        $log_entry->message = $message;
        $log_entry->severity = ucfirst($severity);
        $log_entry->ip_address = $_SERVER['REMOTE_ADDR'];
        
        return JFactory::getDbo()->insertObject('#__jhackguard_logs', $log_entry);
   }
/* Rule DB id: 83 
* Rule name: General GET Filters 
*/
public function rule_83(){
$rule_id = 83;
$rule_name = "General GET Filters";
//Scan the GET array for malicious code

$closure = function($key,$l) use($rule_id, $rule_name, &$closure)
{
  if(is_array($l))
  {
    foreach($l as $subkey=>$subl)
    {
      $closure($subkey,$subl);
    }
    return;
  }
  $jinput = JFactory::getApplication()->input;
  //Filter for eval + base64decode.
  if(preg_match('/\beval\b\s*(.*)\(\s*base64_decode/i',$l))
  {
    //This is bad. Found eval key word followed by base64_decode.
    $this->add_log('Posted variable '.$key.' matched eval + base64_decode pattern in rule with id:'.$rule_id,'standard');
    unset($_GET[$key]);
    $jinput->set($key,null);
    return;
  }
  
  //Filter for eval($scope), where scope would be $_POST, $_GET, $_COOKIE, $_SERVER.
  if(preg_match('/\beval\b\s*(.*)\(\s*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER)/i',$l))
  {
    $this->add_log('Posted variable '.$key.' matched eval(*scope*) pattern in rule with id:'.$rule_id,'standard');
    unset($_GET[$key]);
    $jinput->set($key,null);
    return;
  }
  
  //Filter for document.write + iframe pattern.
  if(preg_match('/document\.write\s*(.*)iframe/i',$l))
  {
    $this->add_log('Posted variable '.$key.' matched document.write + iframe pattern in rule with id:'.$rule_id,'standard');
    unset($_GET[$key]);
    $jinput->set($key,null);
    return;
  }
  
  //Filter for echo, iframe and visibility in the same variable.
  if(stripos($l,'visibility') !== FALSE AND stripos($l,'echo') !== FALSE AND stripos($l,'iframe') !== FALSE)
  {
    $this->add_log('Posted variable '.$key.' matched echo, iframe and visibility pattern in rule with id:'.$rule_id,'standard');
    unset($_GET[$key]);
    $jinput->set($key,null);
    return;
  }
//Filter for SQL injections.
if(preg_match("/((%27)|')\s*(s|%73|%53)(e|%65|%45)(l|%6C|%4C)(e|%65|%45)(c|%63|%43)(t|%74|%54)/ix",$l))
{
	$this->add_log('Posted variable '.$key.' matched SQL injection pattern in rule with id:'.$rule_id,'standard');
	unset($_GET[$key]);
	$jinput->set($key,null);
	return;
}

if(preg_match("/\w*((%27)|')\s*(o|(%6F)|(%4F))(r|(%72)|(%52))/ix",$l))
{
	$this->add_log('Posted variable '.$key.' matched SQL injection pattern in rule with id:'.$rule_id,'standard');
	unset($_GET[$key]);
	$jinput->set($key,null);
	return;
}

if(preg_match("/((%27)|')\s*(u|%75|%55)(n|%6E|%4E)(i|%69|%49)(o|%6F|%4F)(n|%6E|%4E)/ix",$l))
{
	$this->add_log('Posted variable '.$key.' matched SQL injection pattern in rule with id:'.$rule_id,'standard');
	unset($_GET[$key]);
	$jinput->set($key,null);
	return;
}

if(preg_match("/((%27)|')\s*(d|%64|%44)(e|%65|%45)(l|%6C|%4C)(e|%65|%45)(t|%74|%54)(e|%65|%45)/ix",$l))
{
	$this->add_log('Posted variable '.$key.' matched SQL injection pattern in rule with id:'.$rule_id,'standard');
	unset($_GET[$key]);
	$jinput->set($key,null);
	return;
}


if(preg_match("/(union).*(select|update|delete).*(from)/ix",$l))
{
	$this->add_log('Posted variable '.$key.' matched SQL injection pattern in rule with id:'.$rule_id,'standard');
	unset($_GET[$key]);
	$jinput->set($key,null);
	return;
}


};

foreach($_GET as $key=>$l)
{
  $closure($key,$l);
}
} //End of rule_83

/* Rule DB id: 84 
* Rule name: General POST Filers 
*/
public function rule_84(){
$rule_id = 84;
$rule_name = "General POST Filers";
//Scan the POST array for malicious code

$closure = function($key,$l) use($rule_id, $rule_name, &$closure)
{
  if(is_array($l))
  {
    foreach($l as $subkey=>$subl)
    {
      $closure($subkey,$subl);
    }
    return;
  }
  $jinput = JFactory::getApplication()->input;
  //Filter for eval + base64decode.
  if(preg_match('/\beval\b\s*(.*)\(\s*base64_decode/i',$l))
  {
    //This is bad. Found eval key word followed by base64_decode.
    $this->add_log('Posted variable '.$key.' matched eval + base64_decode pattern in rule with id:'.$rule_id,'standard');
    unset($_POST[$key]);
    $jinput->set($key,null);
    return;
  }
  
  //Filter for eval($scope), where scope would be $_POST, $_GET, $_COOKIE, $_SERVER.
  if(preg_match('/\beval\b\s*(.*)\(\s*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER)/i',$l))
  {
    $this->add_log('Posted variable '.$key.' matched eval(*scope*) pattern in rule with id:'.$rule_id,'standard');
    unset($_POST[$key]);
    $jinput->set($key,null);
    return;
  }
  
  //Filter for document.write + iframe pattern.
  if(preg_match('/document\.write\s*(.*)iframe/i',$l))
  {
    $this->add_log('Posted variable '.$key.' matched document.write + iframe pattern in rule with id:'.$rule_id,'standard');
    unset($_POST[$key]);
    $jinput->set($key,null);
    return;
  }
  
  //Filter for echo, iframe and visibility in the same variable.
  if(stripos($l,'visibility') !== FALSE AND stripos($l,'echo') !== FALSE AND stripos($l,'iframe') !== FALSE)
  {
    $this->add_log('Posted variable '.$key.' matched echo, iframe and visibility pattern in rule with id:'.$rule_id,'standard');
    unset($_POST[$key]);
    $jinput->set($key,null);
    return;
  }
//Filter for SQL injections.
if(preg_match("/((%27)|')\s*(s|%73|%53)(e|%65|%45)(l|%6C|%4C)(e|%65|%45)(c|%63|%43)(t|%74|%54)/ix",$l))
{
	$this->add_log('Posted variable '.$key.' matched SQL injection pattern in rule with id:'.$rule_id,'standard');
	unset($_GET[$key]);
	$jinput->set($key,null);
	return;
}

if(preg_match("/\w*((%27)|')\s*(o|(%6F)|(%4F))(r|(%72)|(%52))/ix",$l))
{
	$this->add_log('Posted variable '.$key.' matched SQL injection pattern in rule with id:'.$rule_id,'standard');
	unset($_GET[$key]);
	$jinput->set($key,null);
	return;
}

if(preg_match("/((%27)|')\s*(u|%75|%55)(n|%6E|%4E)(i|%69|%49)(o|%6F|%4F)(n|%6E|%4E)/ix",$l))
{
	$this->add_log('Posted variable '.$key.' matched SQL injection pattern in rule with id:'.$rule_id,'standard');
	unset($_GET[$key]);
	$jinput->set($key,null);
	return;
}

if(preg_match("/((%27)|')\s*(d|%64|%44)(e|%65|%45)(l|%6C|%4C)(e|%65|%45)(t|%74|%54)(e|%65|%45)/ix",$l))
{
	$this->add_log('Posted variable '.$key.' matched SQL injection pattern in rule with id:'.$rule_id,'standard');
	unset($_GET[$key]);
	$jinput->set($key,null);
	return;
}


if(preg_match("/(union).*(select|update|delete).*(from)/ix",$l))
{
	$this->add_log('Posted variable '.$key.' matched SQL injection pattern in rule with id:'.$rule_id,'standard');
	unset($_GET[$key]);
	$jinput->set($key,null);
	return;
}


};

foreach($_POST as $key=>$l)
{
  $closure($key,$l);
}
} //End of rule_84

/* Rule DB id: 85 
* Rule name: Com_seminar XSS 
*/
public function rule_85(){
$rule_id = 85;
$rule_name = "Com_seminar XSS";
    # joomla com_seminar Cross site scripting Vulnerability
    # http://cxsecurity.com/issue/WLB-2013090184

    if(
      isset($_REQUEST['option']) 
      AND $_REQUEST['option'] == "com_seminar" 
      AND isset($_REQUEST['search']) 
      AND stripos($_REQUEST['search'],'onmouseover') !== FALSE
    ) {
      $this->add_log('Posted variable '.$key.' matched com_seminar XSS in rule with id:'.$rule_id,'standard');
      die(include(JPATH_ADMINISTRATOR.'/components/com_jhackguard/filter_match_error.html'));
    }
} //End of rule_85

/* Rule DB id: 86 
* Rule name: G2Bridge Component Lfi 
*/
public function rule_86(){
$rule_id = 86;
$rule_name = "G2Bridge Component Lfi";
// joomla com_g2bridge Components Lfi
// http://cxsecurity.com/issue/WLB-2013060227

if(isset($_REQUEST['option']) 
  AND isset($_REQUEST['controller'])
  AND strtolower($_REQUEST['option']) == "com_g2bridge"
  )
{
  if(preg_match('/(tmp|etc|dev|root|bin|sbin|lib|lib64|tftpboot|data|onapp|boot|home|backup|net|misc|sys|var|selinux|lost\+found|media|mnt|opt|srv|usr)/ix', $_REQUEST['controller'])){
    $this->add_log('Posted variable '.$key.' matched com_g2bridge attack pattern in rule with id:'.$rule_id,'standard');
    die(include(JPATH_ADMINISTRATOR.'/components/com_jhackguard/filter_match_error.html'));
  }
}
} //End of rule_86

/* Rule DB id: 87 
* Rule name: JVComment SQL Injection 
*/
public function rule_87(){
$rule_id = 87;
$rule_name = "JVComment SQL Injection";
	# Joomla JV Comment 3.0.2 SQL Injection
    # http://packetstormsecurity.com/files/124916/Joomla-JV-Comment-3.0.2-SQL-Injection.html

    if(
      isset($_REQUEST['option']) 
      AND $_REQUEST['option'] == "com_jvcomment" 
      AND isset($_REQUEST['task']) 
      AND isset($_REQUEST['id'])
    ) {
      if(!preg_match('/^[1-9][0-9]{0,15}$/',$_REQUEST['id']))
      {
        $this->add_log('Posted variable '.$key.' matched JV Comment 3.0.2 SQL Injection pattern in rule with id:'.$rule_id,'standard');
        die(include(JPATH_ADMINISTRATOR.'/components/com_jhackguard/filter_match_error.html'));
      }
    }
} //End of rule_87

/* Rule DB id: 88 
* Rule name: JVideoClip Blind SQL Injection 
*/
public function rule_88(){
$rule_id = 88;
$rule_name = "JVideoClip Blind SQL Injection";
// Joomla JVideoClip Blind SQL Injection
// http://packetstormsecurity.com/files/123340/joomlajvideoclip-sql.txt
if(
  isset($_REQUEST['option']) 
  AND $_REQUEST['option'] == "com_jvideoclip" 
  AND isset($_REQUEST['view']) 
  AND $_REQUEST['view'] == "search"
  AND isset($_REQUEST['type']) 
  AND $_REQUEST['type'] == "user" 
  AND isset($_REQUEST['uid'])
)
{
	if(!preg_match('/^[1-9][0-9]{0,15}$/',$_REQUEST['uid']))
  {
    $this->add_log('Posted variable '.$key.' matched JVideoClip blind SQL injection pattern in rule with id:'.$rule_id,'standard');
    die(include(JPATH_ADMINISTRATOR.'/components/com_jhackguard/filter_match_error.html'));
  }
}
} //End of rule_88

/* Rule DB id: 89 
* Rule name: redSHOP 1.2 SQL Injection 
*/
public function rule_89(){
$rule_id = 89;
$rule_name = "redSHOP 1.2 SQL Injection";
    # Joomla redSHOP 1.2 SQL Injection
    # http://packetstormsecurity.com/files/122757/joomlaredshop12-sql.txt

	if(
      isset($_REQUEST['option']) 
      AND $_REQUEST['option'] == "com_redshop" 
      AND isset($_REQUEST['view']) 
      AND $_REQUEST['view'] == "product"
      AND isset($_REQUEST['task']) 
      AND $_REQUEST['task'] == "addtocompare"
      AND isset($_REQUEST['pid'])
    )
    {
      if(!preg_match('/^[1-9][0-9]{0,15}$/',$_REQUEST['pid']))
      {
        $this->add_log('Posted variable '.$key.' matched redShop 1.2 SQL injection pattern in rule with id:'.$rule_id,'standard');
        die(include(JPATH_ADMINISTRATOR.'/components/com_jhackguard/filter_match_error.html'));
      }
    }
} //End of rule_89

/* Rule DB id: 90 
* Rule name: Virtuemart 2.0.22a SQL Injection 
*/
public function rule_90(){
$rule_id = 90;
$rule_name = "Virtuemart 2.0.22a SQL Injection";
    # 26.Aug.2013
    # Joomla Virtuemart 2.0.22a SQL Injection
    # http://packetstormsecurity.com/files/122925/joomlavirtuemart2022a-sql.txt

    if(
      isset($_REQUEST['option']) 
      AND $_REQUEST['option'] == "com_virtuemart" 
      AND isset($_REQUEST['view']) 
      AND $_REQUEST['view'] == "user"
      AND isset($_REQUEST['task']) 
      AND $_REQUEST['task'] == "removeAddressST"
      AND isset($_REQUEST['virtuemart_userinfo_id'])
    )
    {
      if(!preg_match('/^[1-9][0-9]{0,15}$/',$_REQUEST['virtuemart_userinfo_id']))
      {
        $this->add_log('Posted variable '.$key.' matched Virtuemart 2.0.22a SQL injection pattern in rule with id:'.$rule_id,'standard');
        die(include(JPATH_ADMINISTRATOR.'/components/com_jhackguard/filter_match_error.html'));
      }
    }
} //End of rule_90

} //End of class 