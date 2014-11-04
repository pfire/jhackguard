<?php
/**
 * @version     2.0.0
 * @package     com_jhackguard
 * @copyright   Copyright (C) 2013. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 * @author      Valeri Markov <val@jhackguard.com> - http://www.jhackguard.com/
 */

// No direct access
defined('_JEXEC') or die;

/**
 * Jhackguard helper.
 */
class JhackguardHelper
{
	public static function checkForFilterUpdates()
	{
	        //Perform input rules search.
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

		//Include the JSONRPC client file.
		require_once(JPATH_ADMINISTRATOR.'/components/com_jhackguard/jsonrpc.php');

        	$success = true;
        	$msg = "";

        	//Tracking vars
        	$update = 0;
        	$insert = 0;

        	$client = new JHackGuard_JSONRPC_Client('http://www.jhackguard.com/api/index.php');
        	$result = $client->execute('filters', array('get',0,'free-version'));
		if($client->last_err == null AND is_array($result) and isset($result['success']) and $result['success'] == true and isset($result['data']) and is_array($result['data']))
		{
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
                            		$update++;
                        	}

                    		} else {
                        		$insert++;
                    		}
                	}
		} else {
			$success = false;
			$msg = "Unable to fetch update rules from www.jhackguard.com. ".$client->last_err;
		}
		file_put_contents(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.rules_updated_timestamp', serialize(array('success' => $success, 'msg' => $msg,
			'update' => $update, 'insert' => $insert, 'expires' => time() + 86400)));
		return array('success' => $success, 'msg' => $msg, 'update' => $update, 'insert' => $insert, 'expires' => 0);
	}

	/**
	 * Configure the Linkbar.
	 */
	public static function addSubmenu($vName = '')
	{
        //Process notifications. Adding this here, as it is only rendered when there is data to be rendered 
        //i.e avoids ajax and redirect requests, which we do not want to have such notifications added to.
        
        if(file_exists(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.rules_need_update')){
            JFactory::getApplication()->enqueueMessage(
            JText::_('COM_JHACKGUARD_PLUGIN_RULES_CACHE_REBUILD_NEEDED').' <a href="'. JURI::current().'?option=com_jhackguard&view=filtermaintenance">'.JText::_('COM_JHACKGUARD_TITLE_FILTERMAINTENANCE').'</a>',     
            'warning');  
        }

	//Try to determine if an update was performed in the past 24 hours.
                if(file_exists(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.rules_updated_timestamp'))
                {
                        $rut = unserialize(file_get_contents(JPATH_ADMINISTRATOR.'/components/com_jhackguard/data/.rules_updated_timestamp'));
                        if(is_array($rut) AND $rut['expires'] < time())
                        {
                                $rut = JhackguardHelper::checkForFilterUpdates();
                        }
               	} else {
                       	$rut = JhackguardHelper::checkForFilterUpdates();
               	}

	//Determine if we shuold display an update message.
	if(is_array($rut))
	{
		if($rut['success'])
		{
			if($rut['insert'] > 0 OR $rut['update'] > 0)
			{
				JFactory::getApplication()->enqueueMessage(
	                        'An update to your filters is required. The following items are available: '.$rut['insert'].' new and '.$rut['update'].' updates. Please navigate to <a href="'. JURI::current().'?option=com_jhackguard&view=filtermaintenance">Filter Maintenance</a> page and click on the \'Update Rules\' button, in order to fetch the latest security filters for your Joomla.','warning');
			}
		} else {
			JFactory::getApplication()->enqueueMessage($rut['msg'],'error');
		}
	}

		JHtmlSidebar::addEntry(
			JText::_('COM_JHACKGUARD_TITLE_IPFILTERS'),
			'index.php?option=com_jhackguard&view=ipfilters',
			$vName == 'ipfilters'
		);
		JHtmlSidebar::addEntry(
			JText::_('COM_JHACKGUARD_TITLE_INPUTFILTERS'),
			'index.php?option=com_jhackguard&view=inputfilters',
			$vName == 'inputfilters'
		);
		JHtmlSidebar::addEntry(
			JText::_('COM_JHACKGUARD_TITLE_OUTPUTFILTERS'),
			'index.php?option=com_jhackguard&view=outputfilters',
			$vName == 'outputfilters'
		);
		JHtmlSidebar::addEntry(
			JText::_('COM_JHACKGUARD_TITLE_BOTSCOUTRECORDS'),
			'index.php?option=com_jhackguard&view=botscoutrecords',
			$vName == 'botscoutrecords'
		);
        
        JHtmlSidebar::addEntry(
    		JText::_('COM_JHACKGUARD_TITLE_FILTERMAINTENANCE'),
			'index.php?option=com_jhackguard&view=filtermaintenance',
			$vName == 'filtermaintenance'
		);
      	/* This feature is obsolete and will be completely removed in a future release 
		JHtmlSidebar::addEntry(
			JText::_('COM_JHACKGUARD_TITLE_ONDEMANDSCANS'),
			'index.php?option=com_jhackguard&view=ondemandscans',
			$vName == 'ondemandscans'
		); */

		JHtmlSidebar::addEntry(
            JText::_('COM_JHACKGUARD_TITLE_LOGS'),
            'index.php?option=com_jhackguard&view=logs',
            $vName == 'logs'
        );

	}

	/**
	 * Gets a list of the actions that can be performed.
	 *
	 * @return	JObject
	 * @since	1.6
	 */
	public static function getActions()
	{
		$user	= JFactory::getUser();
		$result	= new JObject;

		$assetName = 'com_jhackguard';

		$actions = array(
			'core.admin', 'core.manage', 'core.create', 'core.edit', 'core.edit.own', 'core.edit.state', 'core.delete'
		);

		foreach ($actions as $action) {
			$result->set($action, $user->authorise($action, $assetName));
		}

		return $result;
	}
}
