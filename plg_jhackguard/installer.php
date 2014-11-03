<?php
// No direct access to this file
defined('_JEXEC') or die;
class plgSystemJhackguardInstallerScript
{

	function postflight( $type, $parent ) {

	$url = "http://www.jhackguard.com/downloads/com_jhackguard.zip";
        // Download the package at the URL given
        $p_file = JInstallerHelper::downloadPackage($url);

        // Was the package downloaded?
        if (!$p_file)
        {
            JError::raiseWarning('', JText::_('COM_INSTALLER_MSG_INSTALL_INVALID_URL'));

            return false;
        }

        $config   = JFactory::getConfig();
        $tmp_dest = $config->get('tmp_path');

        // Unpack the downloaded package file
        $package = JInstallerHelper::unpack($tmp_dest . '/' . $p_file, true);

	// Was the package unpacked?
        if (!$package || !$package['type'])
        {
            if (in_array($installType, array('upload', 'url')))
            {
                JInstallerHelper::cleanupInstall($package['packagefile'], $package['extractdir']);
            }

            $app->setUserState('com_installer.message', JText::_('COM_INSTALLER_UNABLE_TO_FIND_INSTALL_PACKAGE'));
            return false;
        }

        // Get an installer instance
        $installer =  new JInstaller;

        // Install the package
        if (!$installer->install($package['dir']))
        {
            // There was an error installing the package
            $msg = JText::sprintf('COM_INSTALLER_INSTALL_ERROR', JText::_('COM_INSTALLER_TYPE_TYPE_' . strtoupper($package['type'])));
            $result = false;
        }
        else
        {
            // Package installed sucessfully
            $msg = JText::sprintf('COM_INSTALLER_INSTALL_SUCCESS', JText::_('COM_INSTALLER_TYPE_TYPE_' . strtoupper($package['type'])));
            $result = true;
        }

        // Set some model state values
        $app    = JFactory::getApplication();
        $app->enqueueMessage($msg);
        $app->setUserState('com_installer.message', $installer->message);
        $app->setUserState('com_installer.extension_message', $installer->get('extension_message'));
        $app->setUserState('com_installer.redirect_url', $installer->get('redirect_url'));

        // Cleanup the install files
        if (!is_file($package['packagefile']))
        {
            $config = JFactory::getConfig();
            $package['packagefile'] = $config->get('tmp_path') . '/' . $package['packagefile'];
        }

        JInstallerHelper::cleanupInstall($package['packagefile'], $package['extractdir']);
	$app->enqueueMessage("The default installation of jHackGuard has no filters included. Please download the latest filters by going to the '<b>Filter Maintenance</b>' page in the component menu.","error");
 	
	}
}
