<?php
/**
 * @version     2.0.0
 * @package     com_jhackguard
 * @copyright   Copyright (C) 2013. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 * @author      Valeri Markov <val@jhackguard.com> - http://www.jhackguard.com/
 */

// No direct access.
defined('_JEXEC') or die;

jimport('joomla.application.component.controlleradmin');

/**
 * Ondemandscans list controller class.
 */
class JhackguardControllerOndemandscans extends JControllerAdmin
{
	/**
	 * Proxy for getModel.
	 * @since	1.6
	 */
	public function getModel($name = 'ondemandscan', $prefix = 'JhackguardModel', $config=array())
	{
		$model = parent::getModel($name, $prefix, array('ignore_request' => true));
		return $model;
	}
    
    
	/**
	 * Method to save the submitted ordering values for records via AJAX.
	 *
	 * @return  void
	 *
	 * @since   3.0
	 */
	public function saveOrderAjax()
	{
		// Get the input
		$input = JFactory::getApplication()->input;
		$pks = $input->post->get('cid', array(), 'array');
		$order = $input->post->get('order', array(), 'array');

		// Sanitize the input
		JArrayHelper::toInteger($pks);
		JArrayHelper::toInteger($order);

		// Get the model
		$model = $this->getModel();

		// Save the ordering
		$return = $model->saveorder($pks, $order);

		if ($return)
		{
			echo "1";
		}

		// Close the application
		JFactory::getApplication()->close();
	}

	public function verify_integrity()
	{
		if(file_exists(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/scans/rules.php'))
		{
			include_once(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/scans/rules.php');
			echo(json_encode(array("success"=>true,"id" => time())));
		} else {
			echo(json_encode(array("success" => false,"msg" => "Scan rules.php file is missing")));
		}
	}

	public function build_files()
	{
		$id = 0;
		$partial_stop = 0;
		$maxSize = 0;
		$indexStep = 0;
		$maxInserts = 0;
		$files = array();

		if(isset($_POST['partialStop']))
		{
			$partial_stop = (int)$_POST['partialStop'];
		}

		//Max Filesize check
		if(isset($_POST['maxSize']))
		{
			$maxSize = (int)$_POST['maxSize'];
		}
		if(!$maxSize)
		{
			$maxSize = 5242880; //Default value.
		}

		//IndexStep check
		if(isset($_POST['indexStep']))
		{
			$indexStep = (int)$_POST['indexStep'];
		}

		if(!$indexStep)
		{
			$indexStep = 3000;
		}

		//MaxInserts check
		if(isset($_POST['maxInserts']))
		{
			$maxInserts = (int)$_POST['maxInserts'];
		}

		if(!$maxInserts)
		{
			$maxInserts = 300;
		}



		chdir(JPATH_ROOT);

		//If we don't have a partial stop count, then this is a new request.
		//We should therefore clear the database.
		if(!$partial_stop)
		{
			$db = JFactory::getDbo();
	        $query = $db->getQuery(true);      
	        $db->setQuery("DELETE FROM ".$db->quoteName('#__jhackguard_scan_files')); 
	        $db->query(); 
		}
  

		$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator('./'));
	    /* And off we go into the loop */
	    $sql_delimiter = 0;
	    $total_count = 0;
	    $stopped = 0;

	    while($it->valid()) {
	    		//We do no need ., .., or directories. Only files.
	    		if (!$it->isDot() AND !$it->isDir()) 
	    		{
	    			if($it->getSize() > 0 AND $it->getSize() < $maxSize)
	    			{
	    				//We also do not need empty files or files bigger than 5MB.
	    				$total_count++;
	    				if($partial_stop > 0 AND $partial_stop > $total_count)
	    				{
	    					$it->next(); 
	    					continue; //We don't want these items. We indexed them the last run.
	    				}
	    				$files[] = $it->getRealPath();
	    				$sql_delimiter++;
			    		if($sql_delimiter > $maxInserts)
			    		{
			    			//Perform insert.
			    			$db = JFactory::getDbo();
							$query = $db->getQuery(true);

							$query->insert($db->quoteName('#__jhackguard_scan_files'));
							$query->columns('fname');
							foreach($files as $path)
							{
								$query->values($db->quote($path));
							}
							$db->setQuery($query);
							$db->query();
							//Reset sql_delimiter
							$sql_delimiter = 0;
							//Reset files array
							$files = array();
			    		}
			    		if($total_count == ($partial_stop +$indexStep))
			    		{
			    			$stopped = 1;
			    			break;//We have reached the 3k limit per run.
			    		}
	    			}
	    		}
	    		$it->next();
	    }

	  	//Did we miss to import the last batch of the files?
	  	if(count($files) > 0)
	  	{
	  		//Yup..
	  		$db = JFactory::getDbo();
			$query = $db->getQuery(true);

			$query->insert($db->quoteName('#__jhackguard_scan_files'));
			$query->columns('fname');
			foreach($files as $path)
			{
				$query->values($db->quote($path));
			}
			$db->setQuery($query);
			$db->query();
			$files = array();
	  	}
        if($stopped){
        	$partial_stop = $partial_stop + $indexStep;
        	echo(json_encode(array("success" => false,"partialStop" => $partial_stop, "partialRun" => true)));
        } else {
        	//Seems like we finished successfully. WOOHOO!
        	//And the total count is...
		  	$db = JFactory::getDbo();
			$query = $db->getQuery(true);
			$query->select("COUNT(*) as total");
	        $query->from($db->quoteName('#__jhackguard_scan_files'));        
	        $db->setQuery($query);
	        $list = $db->loadColumn(); 
        	echo(json_encode(array("success" => true,"count" =>$list[0])));
        }
	}

	public function scan_files()
	{
		$dir = JPATH_ROOT;
		$id = 0;
		$maxFiles = 100;
		$start = 0;

		/* Files to be ignored by the scanner */
		$ignoreFiles = array(
				JPATH_ROOT.'/libraries/phpmailer/smtp.php', //The standard SMTP mailer of Joomla.
				JPATH_ROOT.'/libraries/joomla/microdata/types.json',
				JPATH_ROOT.'/administrator/components/com_jhackguard/data/input_rules.php', //Our input rules.
                JPATH_ROOT.'/administrator/components/com_jhackguard/data/backups/input_rules.backup.php', //Backup of our input rules.
				JPATH_ROOT.'/administrator/components/com_jhackguard/data/temp_rules.php', //Our input rules temp file.
				JPATH_ROOT.'/administrator/components/com_jhackguard/data/scans/rules.php', //Our own security rules
				JPATH_ROOT.'/media/editors/codemirror/js/php.js', // Default codemirror php tags, contains eval and pregmatch keys
				JPATH_ROOT.'/media/editors/tinymce/tinymce.min.js' // Same as codemirror
		);

		if(isset($_POST['maxFiles']))
		{
			$maxFiles = (int) $_POST['maxFiles'];
			if($maxFiles == 0)
			{
				$maxFiles = 100;
			}
		}

		if(isset($_POST['startFrom']))
		{
			$start = (int)$_POST['startFrom'];
		}

		if(isset($_POST['id']) AND strlen($_POST['id']) >0)
		{
			$id = (int)$_POST['id'];
		} else {
			echo(json_encode(array("success" => false,"msg" => "Missing request id value.")));
			return false;
		}

		chdir(JPATH_ROOT);

		//Rules file, verified by a previous AJAX call. TODO: verify it exists anyway...
		include_once(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/scans/rules.php');

		//Hits, if any, will be written here
		$hits = array();
		//DB stuff..
		$db = JFactory::getDbo();
        
        // Create a new query object.
        $query = $db->getQuery(true);
        $query->select("DISTINCT (".$db->quoteName('fname').")");
        $query->from($db->quoteName('#__jhackguard_scan_files'));
        $query->order('id ASC');
        $db->setQuery($query,$start,$maxFiles);
        $list = $db->loadObjectList();

        foreach($list as $file)
        {
        	//Check if file is to be ignored.
        	if(in_array($file->fname,$ignoreFiles))
        	{
        		continue;
        	}

        	//Not an ignored file.Continue checking...
        	$it = new SplFileInfo($file->fname);
        	if($it->isFile() AND $it->isReadable())
        	{
        		$s = new JHackGuard_OnDemand_Scan_Rules();
        		$s->scan($it);
        		if($s->score > 99)
        		{
        			$hits[] = array(
        				'filename' => $file->fname,
        				'score' => $s->score,
        				'details' => $s->explain
        			);
        		}
        	}
        }
        //We should insert the hits now, if any.
        if(count($hits) > 0)
        {
        	$db = JFactory::getDbo();
			$query = $db->getQuery(true);

			$query->insert($db->quoteName('#__jhackguard_scan_hits'));
			$query->columns('fname, score, details, scan_id');
			foreach($hits as $hit)
			{
				$ins = array($db->quote($hit['filename']), $db->quote($hit['score']), $db->quote(serialize($hit['details'])),$db->quote($id));
				$query->values(implode(',', $ins));
			}
			$db->setQuery($query);
			$db->query();
        }

        //Shall we continue?
        if(count($list) < $maxFiles)
        {
        	$continue = false; //Seems like results from db were less than the max files.
        } else {
        	$continue = true;
        }

        echo(json_encode(array("success" => true,"continue" =>$continue, "totalChecked" => count($list))));
	}

	public function delete_results()
	{
		$id = 0;

		if(isset($_POST['id']))
		{
			$id = (int)$_POST['id'];
		}

		if(!$id)
		{
			echo(json_encode(array("success" => false,"msg" => "Missing request id value.")));
			return false;
		}

		$db = JFactory::getDbo();
	    $query = $db->getQuery(true);      
	    $query->delete($db->quoteName('#__jhackguard_scan_hits'));
	    $query->where($db->quoteName('scan_id') . ' = '. $db->quote($id));
		$db->setQuery($query);
	    $db->query();

	    echo(json_encode(array("success" => true)));
	}

	public function show_results()
	{
		$id = 0;

		if(isset($_POST['id']))
		{
			$id = (int)$_POST['id'];
		}

		if(!$id)
		{
			echo(json_encode(array("success" => false,"msg" => "Missing request id value.")));
			return false;
		}

		$db = JFactory::getDbo();
        
        // Create a new query object.
        $query = $db->getQuery(true);
        $query->select($db->quoteName(array('fname', 'score','details','scan_id')));
        $query->from($db->quoteName('#__jhackguard_scan_hits'));
        $query->where($db->quoteName('scan_id') . ' = '. $db->quote($id));
        $query->order('id ASC');
        $db->setQuery($query);
        $list = $db->loadObjectList();

        //This is our response container.
        $html = "";

        foreach($list as $item)
        {
        	$html = $html. '<div class="well"><strong>File</strong>: <span>'.$item->fname.'</span>';
        	$html = $html. '<br/><strong>Score</strong>: '.$item->score;
        	$html = $html. '<br/><strong>Details</strong>: ';
        	$explain = unserialize($item->details);
        	foreach($explain as $line)
        	{
        		$html = $html.'<br/>'.$line;
        	}
        	$html = $html . '</div><br/>';
        }

        //Or, if the list was empty..
        if($html == "")
        {
        	$html = "<div class='well'><center>No malicious code was found!</center></div>";
        }
        echo(json_encode(array("success" => true,"html" => $html)));
	}

}
