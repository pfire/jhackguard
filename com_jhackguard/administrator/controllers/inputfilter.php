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

jimport('joomla.application.component.controllerform');

/**
 * Inputfilter controller class.
 */
class JhackguardControllerInputfilter extends JControllerForm
{

    function __construct() {
        $this->view_list = 'inputfilters';
        parent::__construct();
    }
}