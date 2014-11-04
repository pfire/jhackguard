<?php
/**
 * @version     2.0.0
 * @package     com_jhackguard
 * @copyright   Copyright (C) 2013. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 * @author      Valeri Markov <val@jhackguard.com> - http://www.jhackguard.com/
 */


// no direct access
defined('_JEXEC') or die;

// Access check.
if (!JFactory::getUser()->authorise('core.manage', 'com_jhackguard')) 
{
	throw new Exception(JText::_('JERROR_ALERTNOAUTHOR'));
}

//Check if our plugin is enabled. If not, issue a warning to the user.
//Redirects will enqueue the message twice, we'll go through the message queue 
//and check if we have this message already enqueued.
$jhackguard_msg_enqueued = 0;
foreach(JFactory::getApplication()->getMessageQueue() as $msg)
{
    if($msg['message'] == (JText::_('COM_JHACKGUARD_PLUGIN_NOT_ENABLED').' <a href="'. JURI::current().'?option=com_plugins&view=plugins&filter_search=jhackguard">'.JText::_('COM_JHACKGUARD_PLUGINS_PAGE').'</a>'))
    {
        $jhackguard_msg_enqueued = 1;
    }
}
if(!JPluginHelper::isEnabled('system', 'jhackguard') and !$jhackguard_msg_enqueued){
    JFactory::getApplication()->enqueueMessage(
        JText::_('COM_JHACKGUARD_PLUGIN_NOT_ENABLED').' <a href="'. JURI::current().'?option=com_plugins&view=plugins&filter_search=jhackguard">'.JText::_('COM_JHACKGUARD_PLUGINS_PAGE').'</a>',     
    'error');    
    }

// Include dependancies
jimport('joomla.application.component.controller');

$controller	= JControllerLegacy::getInstance('Jhackguard');
$controller->execute(JFactory::getApplication()->input->get('task'));
$controller->redirect();
