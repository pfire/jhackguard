<?php
/**
 * @version     2.2.3
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

		//Perform input rules search.
		// Get a db connection.
        $db = JFactory::getDbo();

        //Fetch the output filters from the database.
        $query = $db->getQuery(true);
        $query->select($db->quoteName(array('id')));
        $query->from($db->quoteName('#__jhackguard_input_filters'));
        $db->setQuery($query);
        $list = $db->loadObjectList();
       	if(!count($list))
		{
			JFactory::getApplication()->enqueueMessage(
			'There are currently no input filters enabled. If you have just installed the extension, please navigate to <a href="'. JURI::current().'?option=com_jhackguard&view=filtermaintenance">Filter Maintenance</a> page and click on the \'Update Rules\' button, in order to fetch the latest filters for your app.','warning'); 
 		}
		unset($db,$query,$list);

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
			JText::_('COM_JHACKGUARD_TITLE_LOGS'),
			'index.php?option=com_jhackguard&view=logs',
			$vName == 'logs'
		);
        
        JHtmlSidebar::addEntry(
    		JText::_('COM_JHACKGUARD_TITLE_FILTERMAINTENANCE'),
			'index.php?option=com_jhackguard&view=filtermaintenance',
			$vName == 'filtermaintenance'
		);
        
		JHtmlSidebar::addEntry(
			JText::_('COM_JHACKGUARD_TITLE_ONDEMANDSCANS'),
			'index.php?option=com_jhackguard&view=ondemandscans',
			$vName == 'ondemandscans'
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
