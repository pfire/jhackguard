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

JHtml::addIncludePath(JPATH_COMPONENT.'/helpers/html');
JHtml::_('bootstrap.tooltip');
JHtml::_('behavior.multiselect');
JHtml::_('formbehavior.chosen', 'select');

// Import CSS
$document = JFactory::getDocument();
$document->addStyleSheet('components/com_jhackguard/assets/css/jhackguard.css');

?>
<script type="text/javascript">
    jQuery( document ).ready(function( $ ) {
        $("#rebuild_button").click(function(e){
            clear_console();
            rebuild_rules();
        });

        $("#jhc_update").click(function(e)
        {
            e.preventDefault();
            clear_console();
            jhc_update_start();
        });

        $("#factory_reset_btn").click(function(e)
        {
            e.preventDefault();
            $('#mymodal').modal('toggle');
        });

        $("#confirm_factory_reset").click(function(e)
        {
            e.preventDefault();
            $('#mymodal').modal('toggle');
            clear_console();
            wipe_filters();
        });



        function wipe_filters()
        {
            $("#factory_reset_btn").attr("disabled", "disabled");
             $("#j_console").append("<strong><?php echo JText::_( 'COM_JHACKGUARD_STARTING_REMOVAL_PROCESS' );?>...</strong><br/>");
             $("#j_console").append("<?php echo JText::_( 'COM_JHACKGUARD_REMOVE_RULES' );?>...");
             $.post( "index.php?option=com_jhackguard&task=filtermaintenance.jhc_wipe&view=filtermaintenance&format=raw", { cachePrevent: "1", "<?php echo JSession::getFormToken();?>": "1"})
                .done(function( data ) {
                    data = $.parseJSON(data);
                    if(data.success){
                        $("#j_console").append("<span style='color: green;'> <?php echo JText::_( 'COM_JHACKGUARD_DONE' );?></span> <br/>");
                        jhc_update_start();
                    } else {
                        $("#j_console").append("<span style='color: red;'> <?php echo JText::_( 'COM_JHACKGUARD_FAILED' );?>: </span>"+data.msg);
                    }
                    $("#factory_reset_btn").removeAttr("disabled");
                })
                .fail(function( data) {
                    $("#j_console").append("<span style='color: red;'> <?php echo JText::_( 'COM_JHACKGUARD_FAILED' );?></span>");
                    $("#factory_reset_btn").removeAttr("disabled");
                }); 
        }

        function jhc_update_start()
        {
            $("#jhc_update").attr("disabled", "disabled");
             $("#j_console").append("<strong>Starting update...</strong><br/>");
             $("#j_console").append("Checking for available updates...");
             $.post( "index.php?option=com_jhackguard&task=filtermaintenance.jhc_update&view=filtermaintenance&format=raw", { cachePrevent: "1", "<?php echo JSession::getFormToken();?>": "1"})
                .done(function( data ) {
                    data = $.parseJSON(data);
                    if(data.success){
                        $("#j_console").append("<span style='color: green;'> Done</span> (updated: "+data.updated+" new: "+data.inserted+")<br/>");
                        rebuild_rules();
                    } else {
                        $("#j_console").append("<span style='color: red;'> <?php echo JText::_( 'COM_JHACKGUARD_FAILED' );?>: </span>"+data.msg);
                    }
                    $("#jhc_update").removeAttr("disabled");
                })
                .fail(function( data) {
                    $("#j_console").append("<span style='color: red;'> <?php echo JText::_( 'COM_JHACKGUARD_FAILED' );?></span>");
                    $("#jhc_update").removeAttr("disabled");
                }); 
        }
        
        function clear_console()
        {
            $("#j_console").html("");
			$("#j_console_container").removeClass("hide");
        }
        
        function rebuild_rules()
        {
            $("#rebuild_button").attr("disabled", "disabled");
             $("#j_console").append("<strong>Starting rebuild procedure...</strong><br/>");
             $("#j_console").append("Creating backup of the current filters...");
             $.post( "index.php?option=com_jhackguard&task=filtermaintenance.backup&view=filtermaintenance&format=raw", { cachePrevent: "1", "<?php echo JSession::getFormToken();?>": "1"})
                .done(function( data ) {
                    data = $.parseJSON(data);
                    if(data.success){
                        $("#j_console").append("<span style='color: green;'> Done</span><br/>");
                        build_new_file();
                    } else {
                        $("#j_console").append("<span style='color: red;'> <?php echo JText::_( 'COM_JHACKGUARD_FAILED' );?>: </span>"+data.msg);
                    }
                    $("#rebuild_button").removeAttr("disabled");
                })
                .fail(function( data) {
                    $("#j_console").append("<span style='color: red;'> <?php echo JText::_( 'COM_JHACKGUARD_FAILED' );?></span>");
                    $("#rebuild_button").removeAttr("disabled");
                }); 
        }
        
        function build_new_file()
        {
            $("#j_console").append("Building current rules cache file...");
            $.post( "index.php?option=com_jhackguard&task=filtermaintenance.build&format=raw", { cachePrevent: "1", "<?php echo JSession::getFormToken();?>": "1" })
                .done(function( data ) {
                    try {
                        data = $.parseJSON(data);
                        if(data.success){
                            $("#j_console").append("<span style='color: green;'> Done</span><br/>");
                        }
                        console.log(data);
                        test_new_file();
                    } catch (e){
                        $("#j_console").append("<span style='color: red;'> <?php echo JText::_( 'COM_JHACKGUARD_FAILED' );?> - Unexpected response from server: </span>"+data);
                        clean_up();
                    }

                })
                .fail(function( data) {
                    $("#j_console").append("<span style='color: red;'><?php echo JText::_( 'COM_JHACKGUARD_FAILED' );?></span>");
                    $("#rebuild_button").removeAttr("disabled");
                    clean_up();
                }); 
        }
        
        function test_new_file()
        {
            $("#j_console").append("Verifying new rules syntax...");
            $.post( "index.php?option=com_jhackguard&task=filtermaintenance.verify&format=raw", { cachePrevent: "1", "<?php echo JSession::getFormToken();?>": "1" })
                .done(function( data ) {
                    try {
                        data = $.parseJSON(data);
                        if(data.success){
                            $("#j_console").append("<span style='color: green;'> Done</span><br/>");
                            deploy_rules();
                        }
                        console.log(data);
                    } catch (e){
                        $("#j_console").append("<span style='color: red;'> <?php echo JText::_( 'COM_JHACKGUARD_FAILED' );?> - Unexpected response from server: </span>"+data);
                        clean_up();
                    }

                })
                .fail(function( data) {
                    $("#j_console").append("<span style='color: red;'><?php echo JText::_( 'COM_JHACKGUARD_FAILED' );?></span>");
                    $("#rebuild_button").removeAttr("disabled");
                    clean_up();
                }); 
        }
        
        function deploy_rules()
        {
            $("#j_console").append("Deploying new rules...");
            $.post( "index.php?option=com_jhackguard&task=filtermaintenance.deploy&format=raw", { cachePrevent: "1", "<?php echo JSession::getFormToken();?>": "1" })
                .done(function( data ) {
                    try {
                        data = $.parseJSON(data);
                        if(data.success){
                            $("#j_console").append("<span style='color: green;'> Done</span><br/>");
                            $("#j_console").append("<strong>Cache file has been successfully rebuilt!</strong>");
                        }
                        console.log(data);
                    } catch (e){
                        $("#j_console").append("<span style='color: red;'> <?php echo JText::_( 'COM_JHACKGUARD_FAILED' );?> - Unexpected response from server: </span>"+data);
                    }

                })
                .fail(function( data) {
                    $("#j_console").append("<span style='color: red;'><?php echo JText::_( 'COM_JHACKGUARD_FAILED' );?></span>");
                    $("#rebuild_button").removeAttr("disabled");
                    clean_up();
                });
        }
        
        function clean_up()
        {
            $.post( "index.php?option=com_jhackguard&task=filtermaintenance.cleanup&format=raw", { cachePrevent: "1", "<?php echo JSession::getFormToken();?>": "1" })
                .done(function( data ) {
                console.log('Performed cleanup...');
            })
        }
        
    });
    
</script>

<?php
//Joomla Component Creator code to allow adding non select list filters
if (!empty($this->extra_sidebar)) {
    $this->sidebar .= $this->extra_sidebar;
}
?>

<form action="<?php echo JRoute::_('index.php?option=com_jhackguard&view=ondemandscans'); ?>" method="post" name="adminForm" id="adminForm">
<?php if(!empty($this->sidebar)): ?>
	<div id="j-sidebar-container" class="span2">
		<?php echo $this->sidebar; ?>
	</div>
	<div id="j-main-container" class="span10">
<?php else : ?>
	<div id="j-main-container">
<?php endif;?>
    <fieldset class="form-horizontal">
    <legend>Filters Maintenance Procedures</legend>
    </fieldset>
	    <div class="row-fluid show-grid">
              <div class="span4 well">
                    <center><button id="rebuild_button" class="btn btn-primary" type="button">Rebuild rules cache</button></center>
                     <br/><center>This will rebuild the cached file with your current rules.</center>
                    </div>
              <div class="span4 well"><center><button id="jhc_update" class="btn btn-default" type="button">Update rules from JHackGuard.com</button></center>
                    <br/><center>This will update (or insert new) rules from www.jhackguard.com.</center>
              </div>
              <div class="span4 well"><center><button id="factory_reset_btn" class="btn btn-danger" type="button">Revert to factory defaults</button></center>
                    <br/><center>This will reset all firewall rules to their default values.</center>
              </div>
	</div>
    <hr/>
    <div id ="j_console_container" class="row-fluid span10 well hide">
        <div id='j_console'><center> No tasks currently running.</center></div>
    </div>
    
    </div>
</form>

    <div id="mymodal" class="modal hide fade">
    <div class="modal-header">
    <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
    <h3>Confirm Removal</h3>
    </div>
    <div class="modal-body">
    <p>This will delete <b>all</b> your current input filters and will download the latest default filters from <a href="http://www.jhackguard.com">www.jhackguard.com</a>
        Are you sure you would like to continue?</p>
    </div>
    <div class="modal-footer">
    <a href="#" data-dismiss="modal" class="btn">No</a>
    <a id="confirm_factory_reset" class="btn btn-danger">Yes, continue...</a>
    </div>
    </div>
