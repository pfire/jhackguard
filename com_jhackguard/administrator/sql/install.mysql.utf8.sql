CREATE TABLE IF NOT EXISTS `#__jhackguard_bot_scout` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `ordering` int(11) NOT NULL,
  `state` tinyint(1) NOT NULL,
  `checked_out` int(11) NOT NULL,
  `checked_out_time` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `ip_address` varchar(255) NOT NULL,
  `result` varchar(255) NOT NULL,
  `expires` date NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

CREATE TABLE IF NOT EXISTS `#__jhackguard_input_filters` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `ordering` int(11) NOT NULL,
  `state` tinyint(1) NOT NULL,
  `checked_out` int(11) NOT NULL,
  `checked_out_time` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `created_by` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `code` text NOT NULL,
  `rule_action` text NOT NULL,
  `core_id` int(11) NOT NULL DEFAULT '0',
  `core_version` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

INSERT INTO `#__jhackguard_input_filters` (`id`, `ordering`, `state`, `checked_out`, `checked_out_time`, `created_by`, `name`, `code`, `rule_action`, `core_id`, `core_version`) VALUES
(1, 0, 1, 0, '0000-00-00 00:00:00', 0, 'General GET Filters', '//Scan the GET array for malicious code\r\n$log = "";\r\n\r\n$closure = function($key,$l) use($rule_id, $rule_name, &$closure,&$log)\r\n{\r\n  if(is_array($l))\r\n  {\r\n    foreach($l as $subkey=>$subl)\r\n    {\r\n      $closure($subkey,$subl);\r\n    }\r\n    return;\r\n  }\r\n  $jinput = JFactory::getApplication()->input;\r\n  //Filter for eval + base64decode.\r\n  if(preg_match(''/\\beval\\b\\s*(.*)\\(\\s*base64_decode/i'',$l))\r\n  {\r\n    //This is bad. Found eval key word followed by base64_decode.\r\n    $log = ''Posted variable ''.$key.'' matched eval + base64_decode pattern in rule with id:''.$rule_id;\r\n    unset($_GET[$key]);\r\n    $jinput->set($key,null);\r\n    return;\r\n  }\r\n  \r\n  //Filter for eval($scope), where scope would be $_POST, $_GET, $_COOKIE, $_SERVER.\r\n  if(preg_match(''/\\beval\\b\\s*(.*)\\(\\s*(\\$_GET|\\$_POST|\\$_REQUEST|\\$_COOKIE|\\$_SERVER)/i'',$l))\r\n  {\r\n    $log = ''Posted variable ''.$key.'' matched eval(*scope*) pattern in rule with id:''.$rule_id;\r\n    unset($_GET[$key]);\r\n    $jinput->set($key,null);\r\n    return;\r\n  }\r\n  \r\n  //Filter for document.write + iframe pattern.\r\n  if(preg_match(''/document\\.write\\s*(.*)iframe/i'',$l))\r\n  {\r\n    $log = ''Posted variable ''.$key.'' matched document.write + iframe pattern in rule with id:''.$rule_id;\r\n    unset($_GET[$key]);\r\n    $jinput->set($key,null);\r\n    return;\r\n  }\r\n  \r\n  //Filter for echo, iframe and visibility in the same variable.\r\n  if(stripos($l,''visibility'') !== FALSE AND stripos($l,''echo'') !== FALSE AND stripos($l,''iframe'') !== FALSE)\r\n  {\r\n    $log = ''Posted variable ''.$key.'' matched echo, iframe and visibility pattern in rule with id:''.$rule_id;\r\n    unset($_GET[$key]);\r\n    $jinput->set($key,null);\r\n    return;\r\n  }\r\n//Filter for SQL injections.\r\nif(preg_match("/((%27)|'')\\s*(s|%73|%53)(e|%65|%45)(l|%6C|%4C)(e|%65|%45)(c|%63|%43)(t|%74|%54)/ix",$l))\r\n{\r\n	$log = ''Posted variable ''.$key.'' matched SQL injection pattern in rule with id:''.$rule_id;\r\n	unset($_GET[$key]);\r\n	$jinput->set($key,null);\r\n	return;\r\n}\r\n\r\nif(preg_match("/\\w*((%27)|'')\\s*(o|(%6F)|(%4F))(r|(%72)|(%52))/ix",$l))\r\n{\r\n	$log = ''Posted variable ''.$key.'' matched SQL injection pattern in rule with id:''.$rule_id;\r\n	unset($_GET[$key]);\r\n	$jinput->set($key,null);\r\n	return;\r\n}\r\n\r\nif(preg_match("/((%27)|'')\\s*(u|%75|%55)(n|%6E|%4E)(i|%69|%49)(o|%6F|%4F)(n|%6E|%4E)/ix",$l))\r\n{\r\n	$log = ''Posted variable ''.$key.'' matched SQL injection pattern in rule with id:''.$rule_id;\r\n	unset($_GET[$key]);\r\n	$jinput->set($key,null);\r\n	return;\r\n}\r\n\r\nif(preg_match("/((%27)|'')\\s*(d|%64|%44)(e|%65|%45)(l|%6C|%4C)(e|%65|%45)(t|%74|%54)(e|%65|%45)/ix",$l))\r\n{\r\n	$log = ''Posted variable ''.$key.'' matched SQL injection pattern in rule with id:''.$rule_id;\r\n	unset($_GET[$key]);\r\n	$jinput->set($key,null);\r\n	return;\r\n}\r\n\r\n\r\nif(preg_match("/(union).*(select|update|delete).*(from)/ix",$l))\r\n{\r\n	$log = ''Posted variable ''.$key.'' matched SQL injection pattern in rule with id:''.$rule_id;\r\n	unset($_GET[$key]);\r\n	$jinput->set($key,null);\r\n	return;\r\n}\r\n\r\n\r\n};\r\n\r\nforeach($_GET as $key=>$l)\r\n{\r\n  $closure($key,$l);\r\n  if(strlen($log) > 0){ $this->add_log($log,''standard''); $log = "";}\r\n}', '', 1, 1392193103),
(2, 0, 1, 0, '0000-00-00 00:00:00', 0, 'General POST Filers', '//Scan the GET array for malicious code\r\n$log = "";\r\n\r\n$closure = function($key,$l) use($rule_id, $rule_name, &$closure,&$log)\r\n{\r\n  if(is_array($l))\r\n  {\r\n    foreach($l as $subkey=>$subl)\r\n    {\r\n      $closure($subkey,$subl);\r\n    }\r\n    return;\r\n  }\r\n  $jinput = JFactory::getApplication()->input;\r\n  //Filter for eval + base64decode.\r\n  if(preg_match(''/\\beval\\b\\s*(.*)\\(\\s*base64_decode/i'',$l))\r\n  {\r\n    //This is bad. Found eval key word followed by base64_decode.\r\n    $log = ''Posted variable ''.$key.'' matched eval + base64_decode pattern in rule with id:''.$rule_id;\r\n    unset($_POST[$key]);\r\n    $jinput->set($key,null);\r\n    return;\r\n  }\r\n  \r\n  //Filter for eval($scope), where scope would be $_POST, $_GET, $_COOKIE, $_SERVER.\r\n  if(preg_match(''/\\beval\\b\\s*(.*)\\(\\s*(\\$_GET|\\$_POST|\\$_REQUEST|\\$_COOKIE|\\$_SERVER)/i'',$l))\r\n  {\r\n    $log = ''Posted variable ''.$key.'' matched eval(*scope*) pattern in rule with id:''.$rule_id;\r\n    unset($_POST[$key]);\r\n    $jinput->set($key,null);\r\n    return;\r\n  }\r\n  \r\n  //Filter for document.write + iframe pattern.\r\n  if(preg_match(''/document\\.write\\s*(.*)iframe/i'',$l))\r\n  {\r\n    $log = ''Posted variable ''.$key.'' matched document.write + iframe pattern in rule with id:''.$rule_id;\r\n    unset($_POST[$key]);\r\n    $jinput->set($key,null);\r\n    return;\r\n  }\r\n  \r\n  //Filter for echo, iframe and visibility in the same variable.\r\n  if(stripos($l,''visibility'') !== FALSE AND stripos($l,''echo'') !== FALSE AND stripos($l,''iframe'') !== FALSE)\r\n  {\r\n    $log = ''Posted variable ''.$key.'' matched echo, iframe and visibility pattern in rule with id:''.$rule_id;\r\n    unset($_POST[$key]);\r\n    $jinput->set($key,null);\r\n    return;\r\n  }\r\n//Filter for SQL injections.\r\nif(preg_match("/((%27)|'')\\s*(s|%73|%53)(e|%65|%45)(l|%6C|%4C)(e|%65|%45)(c|%63|%43)(t|%74|%54)/ix",$l))\r\n{\r\n	$log = ''Posted variable ''.$key.'' matched SQL injection pattern in rule with id:''.$rule_id;\r\n	unset($_POST[$key]);\r\n	$jinput->set($key,null);\r\n	return;\r\n}\r\n\r\nif(preg_match("/\\w*((%27)|'')\\s*(o|(%6F)|(%4F))(r|(%72)|(%52))/ix",$l))\r\n{\r\n	$log = ''Posted variable ''.$key.'' matched SQL injection pattern in rule with id:''.$rule_id;\r\n	unset($_POST[$key]);\r\n	$jinput->set($key,null);\r\n	return;\r\n}\r\n\r\nif(preg_match("/((%27)|'')\\s*(u|%75|%55)(n|%6E|%4E)(i|%69|%49)(o|%6F|%4F)(n|%6E|%4E)/ix",$l))\r\n{\r\n	$log = ''Posted variable ''.$key.'' matched SQL injection pattern in rule with id:''.$rule_id;\r\n	unset($_POST[$key]);\r\n	$jinput->set($key,null);\r\n	return;\r\n}\r\n\r\nif(preg_match("/((%27)|'')\\s*(d|%64|%44)(e|%65|%45)(l|%6C|%4C)(e|%65|%45)(t|%74|%54)(e|%65|%45)/ix",$l))\r\n{\r\n	$log = ''Posted variable ''.$key.'' matched SQL injection pattern in rule with id:''.$rule_id;\r\n	unset($_POST[$key]);\r\n	$jinput->set($key,null);\r\n	return;\r\n}\r\n\r\n\r\nif(preg_match("/(union).*(select|update|delete).*(from)/ix",$l))\r\n{\r\n	$log = ''Posted variable ''.$key.'' matched SQL injection pattern in rule with id:''.$rule_id;\r\n	unset($_POST[$key]);\r\n	$jinput->set($key,null);\r\n	return;\r\n}\r\n\r\n\r\n};\r\n\r\nforeach($_POST as $key=>$l)\r\n{\r\n  $closure($key,$l);\r\n  if(strlen($log) > 0){ $this->add_log($log,''standard''); $log = "";}\r\n}', '', 2, 1392193146),
(3, 0, 1, 0, '0000-00-00 00:00:00', 0, 'Com_seminar XSS', '    # joomla com_seminar Cross site scripting Vulnerability\r\n    # http://cxsecurity.com/issue/WLB-2013090184\r\n\r\n    if(\r\n      isset($_REQUEST[''option'']) \r\n      AND $_REQUEST[''option''] == "com_seminar" \r\n      AND isset($_REQUEST[''search'']) \r\n      AND stripos($_REQUEST[''search''],''onmouseover'') !== FALSE\r\n    ) {\r\n      $this->add_log(''Posted variable ''.$key.'' matched com_seminar XSS in rule with id:''.$rule_id,''standard'');\r\n      die(include(JPATH_ADMINISTRATOR.''/components/com_jhackguard/filter_match_error.html''));\r\n    }', '', 3, 1392193180),
(4, 0, 1, 0, '0000-00-00 00:00:00', 0, 'G2Bridge Component Lfi', '// joomla com_g2bridge Components Lfi\r\n// http://cxsecurity.com/issue/WLB-2013060227\r\n\r\nif(isset($_REQUEST[''option'']) \r\n  AND isset($_REQUEST[''controller''])\r\n  AND strtolower($_REQUEST[''option'']) == "com_g2bridge"\r\n  )\r\n{\r\n  if(preg_match(''/(tmp|etc|dev|root|bin|sbin|lib|lib64|tftpboot|data|onapp|boot|home|backup|net|misc|sys|var|selinux|lost\\+found|media|mnt|opt|srv|usr)/ix'', $_REQUEST[''controller''])){\r\n    $this->add_log(''Posted variable ''.$key.'' matched com_g2bridge attack pattern in rule with id:''.$rule_id,''standard'');\r\n    die(include(JPATH_ADMINISTRATOR.''/components/com_jhackguard/filter_match_error.html''));\r\n  }\r\n}', '', 4, 1392193259),
(5, 0, 1, 0, '0000-00-00 00:00:00', 0, 'JVComment SQL Injection', '	# Joomla JV Comment 3.0.2 SQL Injection\r\n    # http://packetstormsecurity.com/files/124916/Joomla-JV-Comment-3.0.2-SQL-Injection.html\r\n\r\n    if(\r\n      isset($_REQUEST[''option'']) \r\n      AND $_REQUEST[''option''] == "com_jvcomment" \r\n      AND isset($_REQUEST[''task'']) \r\n      AND isset($_REQUEST[''id''])\r\n    ) {\r\n      if(!preg_match(''/^[1-9][0-9]{0,15}$/'',$_REQUEST[''id'']))\r\n      {\r\n        $this->add_log(''Posted variable ''.$key.'' matched JV Comment 3.0.2 SQL Injection pattern in rule with id:''.$rule_id,''standard'');\r\n        die(include(JPATH_ADMINISTRATOR.''/components/com_jhackguard/filter_match_error.html''));\r\n      }\r\n    }', '', 5, 1392193292),
(6, 0, 1, 0, '0000-00-00 00:00:00', 0, 'JVideoClip Blind SQL Injection', '// Joomla JVideoClip Blind SQL Injection\r\n// http://packetstormsecurity.com/files/123340/joomlajvideoclip-sql.txt\r\nif(\r\n  isset($_REQUEST[''option'']) \r\n  AND $_REQUEST[''option''] == "com_jvideoclip" \r\n  AND isset($_REQUEST[''view'']) \r\n  AND $_REQUEST[''view''] == "search"\r\n  AND isset($_REQUEST[''type'']) \r\n  AND $_REQUEST[''type''] == "user" \r\n  AND isset($_REQUEST[''uid''])\r\n)\r\n{\r\n	if(!preg_match(''/^[1-9][0-9]{0,15}$/'',$_REQUEST[''uid'']))\r\n  {\r\n    $this->add_log(''Posted variable ''.$key.'' matched JVideoClip blind SQL injection pattern in rule with id:''.$rule_id,''standard'');\r\n    die(include(JPATH_ADMINISTRATOR.''/components/com_jhackguard/filter_match_error.html''));\r\n  }\r\n}', '', 6, 1392193349),
(7, 0, 1, 0, '0000-00-00 00:00:00', 0, 'redSHOP 1.2 SQL Injection', '    # Joomla redSHOP 1.2 SQL Injection\r\n    # http://packetstormsecurity.com/files/122757/joomlaredshop12-sql.txt\r\n\r\n	if(\r\n      isset($_REQUEST[''option'']) \r\n      AND $_REQUEST[''option''] == "com_redshop" \r\n      AND isset($_REQUEST[''view'']) \r\n      AND $_REQUEST[''view''] == "product"\r\n      AND isset($_REQUEST[''task'']) \r\n      AND $_REQUEST[''task''] == "addtocompare"\r\n      AND isset($_REQUEST[''pid''])\r\n    )\r\n    {\r\n      if(!preg_match(''/^[1-9][0-9]{0,15}$/'',$_REQUEST[''pid'']))\r\n      {\r\n        $this->add_log(''Posted variable ''.$key.'' matched redShop 1.2 SQL injection pattern in rule with id:''.$rule_id,''standard'');\r\n        die(include(JPATH_ADMINISTRATOR.''/components/com_jhackguard/filter_match_error.html''));\r\n      }\r\n    }', '', 7, 1392193368),
(8, 0, 1, 0, '0000-00-00 00:00:00', 0, 'Virtuemart 2.0.22a SQL Injection', '    # 26.Aug.2013\r\n    # Joomla Virtuemart 2.0.22a SQL Injection\r\n    # http://packetstormsecurity.com/files/122925/joomlavirtuemart2022a-sql.txt\r\n\r\n    if(\r\n      isset($_REQUEST[''option'']) \r\n      AND $_REQUEST[''option''] == "com_virtuemart" \r\n      AND isset($_REQUEST[''view'']) \r\n      AND $_REQUEST[''view''] == "user"\r\n      AND isset($_REQUEST[''task'']) \r\n      AND $_REQUEST[''task''] == "removeAddressST"\r\n      AND isset($_REQUEST[''virtuemart_userinfo_id''])\r\n    )\r\n    {\r\n      if(!preg_match(''/^[1-9][0-9]{0,15}$/'',$_REQUEST[''virtuemart_userinfo_id'']))\r\n      {\r\n        $this->add_log(''Posted variable ''.$key.'' matched Virtuemart 2.0.22a SQL injection pattern in rule with id:''.$rule_id,''standard'');\r\n        die(include(JPATH_ADMINISTRATOR.''/components/com_jhackguard/filter_match_error.html''));\r\n      }\r\n    }', '', 8, 1392193387),
(9, 0, 1, 0, '0000-00-00 00:00:00', 0, 'Joomla com_wire_immogest SQL Injection vulnerabilities', '    # 21.Feb.2014\r\n    # http://packetstormsecurity.com/files/125243/joomlawireimmogest-sql.txt\r\n    # Joomla Wire Immogest SQL Injection\r\n    if(\r\n      isset($_REQUEST[''option'']) \r\n      AND $_REQUEST[''option''] == "com_wire_immogest" \r\n      AND isset($_REQUEST[''view'']) \r\n      AND isset($_REQUEST[''id''])\r\n    ) {\r\n      if(!is_numeric($_REQUEST[''id'']))\r\n      {\r\n        $this->add_log(''Posted variable ''.$key.'' matched Joomla Wire Immogest SQL Injection pattern in rule with id:''.$rule_id,''standard'');\r\n        die(include(JPATH_ADMINISTRATOR.''/components/com_jhackguard/filter_match_error.html''));\r\n      }\r\n    }', '', 9, 1402193180),
(10, 0, 1, 0, '0000-00-00 00:00:00', 0, 'Joomla Multi Calendar 4.0.2 Cross Site Scripting', '	# 17.Mar.2014\r\n    # Joomla Multi Calendar 4.0.2 Cross Site Scripting\r\n    # http://packetstormsecurity.com/files/125738/joomlamulticalendar-xss.txt\r\n\r\n    if(\r\n      isset($_REQUEST[''option'']) \r\n      AND $_REQUEST[''option''] == "com_multicalendar" \r\n      AND isset($_REQUEST[''task'']) \r\n      AND isset($_REQUEST[''calid''])\r\n    ) {\r\n      if(!is_numeric($_REQUEST[''calid'']))\r\n      {\r\n        $this->add_log(''Posted variable ''.$key.'' matched Joomla Multi Calendar pattern in rule with id:''.$rule_id,''standard'');\r\n        die(include(JPATH_ADMINISTRATOR.''/components/com_jhackguard/filter_match_error.html''));\r\n      }\r\n    }', '', 10, 1402193182),
(11, 0, 1, 0, '0000-00-00 00:00:00', 0, 'Inneradmission SQL Injection', '    # 14.Apr.2014\r\n    # Joomla Inneradmission SQL Injection\r\n    # http://packetstormsecurity.com/files/126062/joomlainneradmission-sql.txt\r\n\r\n    if(\r\n      isset($_REQUEST[''option'']) \r\n      AND $_REQUEST[''option''] == "com_inneradmission" \r\n      AND isset($_REQUEST[''id''])\r\n    ) {\r\n      if(!is_numeric($_REQUEST[''id'']))\r\n      {\r\n        $this->add_log(''Posted variable ''.$key.'' matched Inneradmission SQL Injection pattern in rule with id:''.$rule_id,''standard'');\r\n        die(include(JPATH_ADMINISTRATOR.''/components/com_jhackguard/filter_match_error.html''));\r\n      }\r\n    }', '', 11, 1402193183),
(12, 0, 1, 0, '0000-00-00 00:00:00', 0, 'Spider Form Maker 4.3 SQL Injection', '    # 15.Sep.2014\r\n    # Joomla Spider Form Maker 4.3 SQL Injection\r\n    # http://packetstormsecurity.com/files/128239/joomlaspiderformmaker-sql.txt\r\n\r\n	if(\r\n      isset($_REQUEST[''option'']) \r\n      AND $_REQUEST[''option''] == "com_formmaker" \r\n      AND isset($_REQUEST[''view'']) \r\n      AND isset($_REQUEST[''id''])\r\n    ) {\r\n      if(!is_numeric($_REQUEST[''id'']))\r\n      {\r\n        $this->add_log(''Posted variable ''.$key.'' matched Spider Form Maker 4.3 SQL Injection pattern in rule with id:''.$rule_id,''standard'');\r\n        die(include(JPATH_ADMINISTRATOR.''/components/com_jhackguard/filter_match_error.html''));\r\n      }\r\n    }', '', 12, 1402193184),
(13, 0, 1, 0, '0000-00-00 00:00:00', 0, 'Face Gallery SQL injection', '    # 19.Sep.2014\r\n    # Joomla Face Gallery SQL injection\r\n    # http://packetstormsecurity.com/files/128340/joomlafacegallery-sqltraversal.txt\r\n\r\n	if(\r\n      isset($_REQUEST[''option'']) \r\n      AND $_REQUEST[''option''] == "com_facegallery" \r\n      AND isset($_REQUEST[''view'']) \r\n      AND isset($_REQUEST[''aid''])\r\n    ) {\r\n      if(!is_numeric($_REQUEST[''aid'']))\r\n      {\r\n        $this->add_log(''Posted variable ''.$key.'' matched Face Gallery SQL injection pattern in rule with id:''.$rule_id,''standard'');\r\n        die(include(JPATH_ADMINISTRATOR.''/components/com_jhackguard/filter_match_error.html''));\r\n      }\r\n    }', '', 13, 1402193187);


CREATE TABLE IF NOT EXISTS `#__jhackguard_ip_filters` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `ordering` int(11) NOT NULL,
  `state` tinyint(1) NOT NULL,
  `checked_out` int(11) NOT NULL,
  `checked_out_time` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `created_by` int(11) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `expires` date NOT NULL,
  `rule_type` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

CREATE TABLE IF NOT EXISTS `#__jhackguard_logs` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `severity` varchar(255) NOT NULL,
  `ip_address` varchar(255) NOT NULL,
  `user_agent` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=1 ;

CREATE TABLE IF NOT EXISTS `#__jhackguard_output_filters` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `ordering` int(11) NOT NULL,
  `state` tinyint(1) NOT NULL,
  `checked_out` int(11) NOT NULL,
  `checked_out_time` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `created_by` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `regex` varchar(255) NOT NULL,
  `replacement` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 AUTO_INCREMENT=2 ;

CREATE TABLE IF NOT EXISTS `#__jhackguard_scan_files` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `fname` text CHARACTER SET utf8 NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

CREATE TABLE IF NOT EXISTS `#__jhackguard_scan_hits` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `fname` text CHARACTER SET utf8 NOT NULL,
  `score` int(4) NOT NULL,
  `details` text CHARACTER SET utf8 NOT NULL,
  `scan_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `scan_id` (`scan_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;
