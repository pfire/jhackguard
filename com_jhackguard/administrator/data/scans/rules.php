<?php
/**
 * @version     2.0.0
 * @package     com_jhackguard
 * @copyright   Copyright (C) 2013. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 * @author      Valeri Markov <val@jhackguard.com> - http://www.jhackguard.com/
 */

class JHackGuard_OnDemand_Scan_Rules {

   private $total_rules = 6;
   private $total_global_rules = 5;
   private $contents = "";
   private $reg = array();
   public $score = 0;
   private $f;

   public $explain = array(); 

   public function __construct(){
   }

   public function scan($f)
   {
      $this->f = $f;
      $contents = file($f->getRealPath(), FILE_IGNORE_NEW_LINES  |FILE_SKIP_EMPTY_LINES);
      foreach($contents as $line){
         for($i=1;$i <= $this->total_rules; $i++){
            $rule_name = "rule_".$i;
            $this->$rule_name($line);
            $this->contents .= $line;
         }
      }
        
        //Return at this point if line based checks found too suspicious code
        if($this->score > 99){
             return true;
        } 

      //Run global function scans
      for($i=1;$i <= $this->total_global_rules;$i++){
         $global_rule_name = "global_rule_".$i;
         $this->$global_rule_name();
      }

      if($this->score > 99){
         return true;
      }

      //.htaccess thing
      $this->check_htaccess();

   }

    private function check_htaccess()
    {
    	if($this->f->getFilename() == ".htaccess"){
    	    if(stripos($this->contents,'google') !== FALSE AND stripos($this->contents,'HTTP_REFERER') !== FALSE){
        		$this->score += 100;
        		$this->explain[] = "Found .htaccess referrer entry";
    	    }
    	}
    }

   private function global_rule_1()
   {
      // Search for google_analist pattern. Used by
      // google-something-hackers.html
      if(stripos($this->contents,"google_analist") !== FALSE){
         //Critical
         $this->score += 100;
         $this->explain[] = "Found google_analist pattern";
      }
     if(stripos($this->contents,"tool4spam.com") !== FALSE){
	     $this->score += 100;
         $this->explain[] = "Found google_analist pattern";
      }
      if(stripos($this->contents,"tmp_god") !== FALSE AND stripos($this->contents,"GodSpy") !== FALSE
        AND stripos($this->contents,"makehide") !== FALSE
      ) {
        $this->score += 100;
        $this->explain[] = "'GodSpy'Shell script found.";
      }

	if(stripos($this->contents, "Mass Mailer") !== FALSE)
	{
		$this->score +=100;
		$this->explain[] = "Possible mass mailer";
	}

   }


   private function global_rule_2()
   {
      if(stripos($this->contents,"/etc/passwd") !== FALSE){
         //Bad
         $this->score += 100;
         $this->explain[] = "Found reference to /etc/passwd file.";
      }
   }

   private function global_rule_3()
   {
    	if(stripos($this->contents,'preg_replace("/.*/e"') !== FALSE OR stripos($this->contents,'preg_replace("/.+/e"') !== FALSE){
    	   // Very bad.
    	   $this->score += 100;
    	   $this->explain[] = "Found pregmatch with evaluate flag";
    	}
    }

    private function global_rule_4()
    {
    	if(stripos($this->contents,'hacked by') !== FALSE){
    	    //Pretty much bad.. :)
    	    $this->score += 100;
    	    $this->explain[] = "Found 'hacked by' term. Might be false positive.";
    	}
    }

    private function global_rule_5()
    {
            if(stripos($this->contents,'PHP_OS') !== FALSE AND !array_key_exists('php_os',$this->reg)){
                if(!in_array(md5_file($this->f->getRealPath()),
                array('c3d902f1007e54d1f95b268e4f9643d6','a392bff2e5d22b555bf1e5c098a3eda3','d1c8a277f0cc128b5610db721c70eabd')
        	    )){ 
            	    $this->score += 15;
            	    $this->explain[] = "Found PHP_OS keyword.";
            	    $this->reg['php_os'] = TRUE;
        	    }
        	}
        	if(stripos($this->contents,'extension_loaded') !== FALSE AND !array_key_exists('extension_loaded',$this->reg)){
        	    if(!in_array($this->f->getFilename(), array('php-brief.php','mootools-more.js','php.php','tokenizephp.js','simplepie.php'))){
            	    $this->score += 15;
            	    $this->explain[] = "Found extension_loaded keyword.";
            	    $this->reg['extension_loaded'] = TRUE;
        	    }
        	}
        	if(stripos($this->contents,'socket_create') !== FALSE AND !array_key_exists('socket_create',$this->reg)){
                    if(!in_array(md5_file($this->f->getRealPath()),
                    array('c3d902f1007e54d1f95b268e4f9643d6','a392bff2e5d22b555bf1e5c098a3eda3')
                    )){ 
                        $this->score += 15;
                        $this->explain[] = "Found socket_create keyword.";
            	        $this->reg['socket_create'] = TRUE;
                    }
                }
        	if(stripos($this->contents,'move_uploaded_file') !== FALSE AND !array_key_exists('move_upload',$this->reg)){
            	     if(!in_array($this->f->getFilename(), array('php-brief.php','mootools-more.js','php.php','tokenizephp.js'))){     
                        $this->score += 20;
                        $this->explain[] = "Found move_uploaded_file keyword.";
            	        $this->reg['move_upload'] = TRUE;
            	   }
            }

    	if(stripos($this->contents,'vpsp_version') !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "Found proxy script vpsp";
    	}
    	
    	if(stripos($this->contents,'J3F1N') !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "Found j3f1n mailer script footprints";
    	}

	if(stripos($this->contents,'PHP Bulk Emailer') !== FALSE){
	    $this->score +=100;
	    $this->explain[] = "Found PHP Bulk Emailer script footprints";
	}
    
    	if(stripos($this->contents,'shmop.so') !== FALSE OR stripos($this->contents,'php_shmop.dll') !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "Found shmop keywords.";
    	}
    	if(stripos($this->contents,'h\145\x61\144er') !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "Encoded header tag found in file";
    	}
    	if(stripos($this->contents,'edoced_46esab') !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "Found strrev base64 encode string.";
    	}
    	if(stripos($this->contents,'CgokUGFnZXNDb25maWcgPSBhcnJheQooCgknJyAgICAgICA9PiBhcnJheSgndHJhbWFkb2x8dWx0') !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "Pharma hack footprints found";
    	}

	if(stripos($this->contents,'WSO_VERSION') !== FALSE){
	    $this->score +=100;
	    $this->explain[] = "Shell script footprints.";
	}
    
    	if(stripos($this->contents, '"fro"+"mC"+"harC"+"o"+"de"') !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "Obfuscated fromcharcode string found.";
    	}

	if(stripos($this->contents, 'PostMan Full') !== FALSE){
		$this->score +=100;
		$this->explain[] = "Found PostMan Mailer Script";
	}
	if(stripos($this->contents, 'php_display') !== FALSE AND stripos($this->contents, 'error_404') !== FALSE AND stripos($this->contents, '@file_get_contents') !== FALSE){
		$this->score +=100;
		$this->explain[] = "Remote fetch script found.";
	}

    }

    /*************************************************
    ** These are per line rules **********************
    *************************************************/

   private function rule_1($l){
   
      // eval(anything here)ase64_decode regex search
      if(preg_match('/\beval\b\s*(.*)\(\s*base64_decode/i',$l))
      {
         //This is pretty obvious. Both eval and base64 are present one after
         //another.
         $this->score += 100;
         $this->explain[] = "Found eval+base64decode pattern.";
      } 
 
   }

   private function rule_2($l){
      // Search for eval($_POST or eval($_GET) or request/cookie/etc
      if(preg_match('/\beval\b\s*(.*)\(\s*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER)/i',$l)){
         //This is critical.
         $this->score += 100;
         $this->explain[] = "Found eval+POST/GET on the same line.";
      }
   }

   private function rule_3($l){
	//Search for eval and check if certain conditions are met.
	//skip if file is not a .php file
    if($this->f->getExtension() == "php"){ 
    	if(stripos($l, 'eval') !== FALSE){
    	    //Shell script with obfuscated entries.
    	    if(stripos($l,'$__') !== FALSE){
        		$this->score += 100;
        		$this->explain[] = "Found eval+obfuscated variable names";
    	    }
    	}
    }
   }

   private function rule_4($l){
      // Search for script document.write followed by an iframe
      if(in_array($this->f->getFilename(), array('tiny_mce.js','codemirror.js','mootools.js','customize-controls.min.js')))
	return;
      if($this->f->getExtension() == "js") 
	{
	    if(preg_match('/document\.write\s*(.*)iframe/i',$l)){
		//Probably malicious.
		if(stripos($l, 'http') !== FALSE){
		    //Most probably malicious.
		    $this->score += 100;
		    $this->explain[] = "Found document.write+iframe coupled with http";
		} else {
		    $this->score += 30;
		    $this->explain[] = "Found document.write+iframe";
		}
	    }
	return;
	//No need to execute below lines if it is js.
	}
      if(preg_match('/script\s*(.*)document\.write\s*(.*)iframe/i',$l)){
         //Pretty much critical as well.
         $this->score += 100;
         $this->explain[] = "Found script+document.write+iframe";
      }
   }
   
   private function rule_6($l){
        if(stripos($l,'visibility') !== FALSE AND stripos($l,'echo') !== FALSE AND stripos($l,'iframe') !== FALSE)
        {
            //Contains echo, iframe and visibility keywords in a single line.
            $this->score +=100;
            $this->explain[] = "Found iframe with visibility modifier being printed";
        }
   }

   private function rule_5($l){
    	//Very clever tmp/analog spam inclusion code.
    	if(stripos($l,"@require_once") !== FALSE AND stripos($l,"tmp/analog") !== FALSE){
    	    $this->score +=100;
    	    $this->explain[] = "Found Joomla tmp/analog viagra pattern.";
    	}
    
    	if(!isset($this->reg['long_line']) AND strlen($l) > 500){
            //Not really critical but suspicious.
        	if(stripos($l,'eval') !== FALSE AND $this->f->getExtension() != "js" AND $this->f->getExtension() != "ini"){
        	    //This is rather general. We need to exclude some well know files which are NOT malicious.
        	    if(!in_array(md5_file($this->f->getRealPath()),
        		array('f9b598c3427a2f757e91680c5dd01f47','a367d614cd1ea7577268ac55041297a9','f3ff1685b97265aa491eef9f0aa0bc45')
        	    )){ 
            		$this->score +=50;
            		$this->explain[] = "Found eval in a very long line";
        	    }
        	}
        	if(stripos($l,'urldecode') !== FALSE){
        	    $this->score +=25;
        	    $this->explain[] = "+25p for having urldecode in a very long line";
        	}
             
            if(!in_array(md5_file($this->f->getRealPath()),
        	array('f9b598c3427a2f757e91680c5dd01f47','a367d614cd1ea7577268ac55041297a9','a392bff2e5d22b555bf1e5c098a3eda3','d1c8a277f0cc128b5610db721c70eabd')
    	    )){ 
                //Additional checks for keywords in such a long line
                if(stripos($l,'ini_set') !== FALSE){
            	    $this->score +=15;
            	    $this->explain[] = "+15p for having long line with ini_set";
            	}
            	if(stripos($l,'md5') !== FALSE){
            	    $this->score +=15;
            	    $this->explain[] = "+15p for having long line with md5";
            	}
            
            	if(stripos($l,'mail') !== FALSE){
            	    $this->score +=25;
            	    $this->explain[] = "+25p for having long line with mail command";
            	}

				if(stripos($l,'preg_replace') !== FALSE){
					$this->score+=50;
					$this->explain[] = "+50p for having preg_replace in a very long line";
				}
                 $this->score += 50;
                 $this->explain[] = "+50p. for having a very long line.";
                 $this->reg['long_line'] = TRUE;
	    }
      }
   }
}