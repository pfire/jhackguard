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
JFactory::getLanguage()->load('com_jhackguard');


/**
 * Filtermaintenance controller class.
 */
class JhackguardControllerFiltermaintenance extends JControllerAdmin
{   

    public function backup()
    {
        if(!JSession::checkToken())
        {
           echo json_encode(array('success'=>false, 'msg'=>JText::_( 'COM_JHACKGUARD_INVALID_CSRF' )));
           return;
        }
        file_put_contents(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.disable_input_rules','1',LOCK_EX);
        $success = true;
        $msg = "";
        // Ensure that the backups directory exists
        if(is_dir(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/backups'))
        {
            //Check if there is a current rules.php file.
            if(file_exists(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/input_rules.php'))
            {
                //Make a backup of this file.
                if(!copy(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/input_rules.php', JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/backups/input_rules.backup.php'))
                {
                    $success = false;
                    $msg = JText::_( 'COM_JHACKGUARD_COPY_TO_RULES_FAIL' );
                }
            } // If there is no input_rules.php file, we create no backup, but this is not an error so no fail success message here.
        } else {
            $success = false;
            $msg = JText::_( 'COM_JHACKGUARD_BACKUP_DIR_MISSING' );
        }
        echo json_encode(array('success'=>$success, 'msg' => $msg));
    }
    
    public function build()
    {
        if(!JSession::checkToken())
        {
           echo json_encode(array('success'=>false, 'msg'=>'Invalid CSRF Token.'));
           return;
        }
        //Start building the file code.
        $success = true;
        $msg = "";
        
        $code = "<?php
defined('_JEXEC') or die;

class JHackGuard_Input_Filters {
public \$build_time = ".time().";\n
public \$log_level = 0;

public function __construct()
{
\$this->log_level = JComponentHelper::getParams('com_jhackguard')->get('log_level',1);
}

/* Goes through each method of this class and executes it
** ignores run and add_log methods */

public function run(){
\$methods = get_class_methods('JHackGuard_Input_Filters');
ob_start();
foreach(\$methods as \$m){
    if(!in_array(\$m,array('run','add_log','__construct')))
    {
        \$this->\$m();
    }
}
ob_end_clean();
}

public function add_log(\$message, \$severity)
    {
        /* Compare the system log level and the log request level*/
        \$log_this = FALSE;
        switch(\$severity)
        {
            case 'debug':
                if(\$this->log_level == 2)
                    \$log_this = TRUE;
                    break;
            case 'standard':
                if(\$this->log_level > 0)
                    \$log_this = TRUE;
                    break;
        } 
        //Shall we log?
        if(!\$log_this)
        {
            unset(\$log_this);
            return FALSE;
        }
        unset(\$log_this);
        //We shall log.
        \$log_entry = new stdClass();
        \$log_entry->message = \$message;
        \$log_entry->severity = ucfirst(\$severity);
        \$log_entry->ip_address = \$_SERVER['REMOTE_ADDR'];
        
        return JFactory::getDbo()->insertObject('#__jhackguard_logs', \$log_entry);
   }
";
        
        //Fetch the available rules from the database.
        $db = JFactory::getDbo();
        
        // Create a new query object.
        $query = $db->getQuery(true);
        $query->select($db->quoteName(array('id','name','code','core_id','core_version')));
        $query->from($db->quoteName('#__jhackguard_input_filters'));
        $query->where($db->quoteName('state') . ' = 1');
        $query->order('ordering ASC');
        $db->setQuery($query);
        $result = $db->loadObjectList(); 
        
        //Build the PHP code
        if(!is_null($result)){
        foreach($result as $record)
        {
            $code = $code . "/* Rule DB id: ".$record->id." 
* Rule name: ".$record->name." 
*/
public function rule_".$record->id."(){
\$rule_id = ".$record->id.";
\$rule_name = \"".$record->name."\";
".$record->code."
} //End of rule_".$record->id."\n
";
        }
        }
        
        //Closing class bracket
        $code = $code . "} //End of class ";
        
        //Save the code to a temporary file.
        if(file_put_contents(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/temp_rules.php',$code,LOCK_EX) === FALSE){
            $success = false;
            $msg = "Unable to save code to: ".JPATH_ADMINISTRATOR."/components/com_jhackguard/data/temp_rules.php";
        }
         echo json_encode(array('success'=>$success, 'msg'=>$msg));
    }
    
    public function verify()
    {
        if(!JSession::checkToken())
        {
           echo json_encode(array('success'=>false, 'msg'=>'Invalid CSRF Token.'));
           return;
        }
        //It is usually enough to include the file and instantiate the class.
        //If there is an error, this AJAX call will fail and new rules will not be copied.
        require_once(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/temp_rules.php');
        $instance = new JHackGuard_Input_Filters();
        $msg = $instance->build_time;
        echo json_encode(array('success'=>true,'msg'=>$msg));
        if(file_exists(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.disable_input_rules')){
            unlink(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.disable_input_rules');
        }
    }
    
    public function cleanup()
    {
        if(!JSession::checkToken())
        {
           echo json_encode(array('success'=>false, 'msg'=>'Invalid CSRF Token.'));
           return;
        }
        if(file_exists(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.disable_input_rules')){
            unlink(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.disable_input_rules');
        }
    }
    
    public function deploy()
    {
        if(!JSession::checkToken())
        {
           echo json_encode(array('success'=>false, 'msg'=>'Invalid CSRF Token.'));
           return;
        }

        $success = true;
        $msg = "";
        //Trying to copy temp_rules.php to input_rules.php file.
         if(file_exists(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/temp_rules.php'))
            {
                //Make a backup of this file.
                if(!copy(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/temp_rules.php', JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/input_rules.php'))
                {
                    $success = false;
                    $msg = JText::_( 'COM_JHACKGUARD_COPY_TMP_RULES' );
                } else {
                    //Deployment completed. We need to remove any "need-update" flags.
                    if(file_exists(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.rules_need_update')){
                        unlink(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.rules_need_update');
                    }
		    
		if(file_exists(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.rules_updated_timestamp')){
	        	unlink(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.rules_updated_timestamp');
        	}
                }
            }
        echo json_encode(array('success'=>$success, 'msg'=>$msg));
    }

    public function jhc_wipe()
    {
        if(JSession::checkToken()){
            $db = JFactory::getDbo();
            $query = $db->getQuery(true);      
            $db->setQuery("DELETE FROM ".$db->quoteName('#__jhackguard_input_filters')); 
            $db->query();
            echo json_encode(array('success'=>true));
        } else 
        {
            echo json_encode(array('success'=>false, 'msg'=>'Invalid CSRF Token.'));
        }
    }

    public function jhc_update()
    {
        if(!JSession::checkToken())
        {
           echo json_encode(array('success'=>false, 'msg'=>'Invalid CSRF Token.'));
           return;
        }
        //Include the JSONRPC client file.
        require_once(JPATH_ADMINISTRATOR.'/components/com_jhackguard/jsonrpc.php');
        
        $success = true;
        $msg = "";

        //Tracking vars
        $updated = 0;
        $inserted = 0;

        $client = new JHackGuard_JSONRPC_Client('http://www.jhackguard.com/api/index.php');
        //TODO: use the actual configuration value for the license key
        $result = $client->execute('filters', array('get',0,'free-version'));
        
        if($client->last_err != null)
        {
            $success = false;
            $msg = $client->last_err;
        } else {
            if(is_array($result) and isset($result['success']) and $result['success'] == true and isset($result['data']) and is_array($result['data']))
            {
                //Perform a DB query fetching all core_id's here
                // Get a db connection.
                $db = JFactory::getDbo();
                
                //Fetch the output filters from the database.
                $query = $db->getQuery(true);
                $query->select($db->quoteName(array('id','core_id','core_version')));
                $query->from($db->quoteName('#__jhackguard_input_filters'));
                $query->where($db->quoteName('core_id') . ' > 0');
                $query->order('ordering ASC');
                $db->setQuery($query);
                $list = $db->loadObjectList();

                //Define core list array
                $core_rules = array();
                foreach($list as $core_item)
                {
                    $core_rules[$core_item->core_id] = array(
                        'version' => $core_item->core_version,
                        'id' => $core_item->id
                        );
                }

                foreach($result['data'] as $cid => $cob)
                {
                    if(array_key_exists($cid, $core_rules))
                    {
                        if($cob['version'] > $core_rules[$cid]['version'])
                        {
                            //There is a new version of this particular rule. We need to update it.
                            $object = new stdClass();

                            // Must be a valid primary key value.
                            $object->id = $core_rules[$cid]['id'];
                            $object->name = $cob['name'];
                            $object->core_version = $cob['version'];
                            $object->code = $cob['code'];
                            $result = JFactory::getDbo()->updateObject('#__jhackguard_input_filters', $object, 'id');
                            $updated++;
                        }
                        
                    } else {
                        $object = new stdClass();

                        // Must be a valid primary key value.
                        $object->id = null;
                        $object->name = $cob['name'];
                        $object->core_version = $cob['version'];
                        $object->core_id = $cid;
                        $object->code = $cob['code'];
                        $object->state = 1;
                        $result = JFactory::getDbo()->insertObject('#__jhackguard_input_filters', $object);
                        $inserted++;
                    }
                }
            }
            echo json_encode(array('success' => $success, 'updated'=>$updated, 'inserted' => $inserted, 'msg' => $msg));
        }
        
    }
}
