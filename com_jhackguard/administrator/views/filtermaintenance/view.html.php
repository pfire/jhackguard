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

jimport('joomla.application.component.view');

/**
 * View to edit
 */
class JhackguardViewFiltermaintenance extends JViewLegacy
{
    protected $items;
    protected $pagination;
	protected $state;
    
    public function display($tpl = null)
	{
		$this->state		= $this->get('State');
		// Check for errors.
		if (count($errors = $this->get('Errors'))) {
			throw new Exception(implode("\n", $errors));
		}
        
		JhackguardHelper::addSubmenu('filtermaintenance');
        
		$this->addToolbar();
        
        $this->sidebar = JHtmlSidebar::render();
		parent::display($tpl);
	}
    
   /**
	 * Add the page title and toolbar.
	 *
	 * @since	1.6
	 */
	protected function addToolbar()
	{
		require_once JPATH_COMPONENT.'/helpers/jhackguard.php';

		$state	= $this->get('State');
		JToolBarHelper::title(JText::_('COM_JHACKGUARD_TITLE_FILTERMAINTENANCE'), 'filtermaintenance.png');
        JToolBarHelper::preferences('com_jhackguard');
 
        //Set sidebar action - New in 3.0
		JHtmlSidebar::setAction('index.php?option=com_jhackguard&view=filtermaintenance');
        
        $this->extra_sidebar = '';        
	}
}
