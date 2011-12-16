#!/usr/bin/perl -w
########################################################################
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Plugin : check_aix_errpt.pl 
#
# Description :
# Search and dig Errors reports in errpt output
#
# Sypnosis : 
# ./check_aix_errpt.pl [-h|--help] [-v|--verbose] [-L|--last-minuts] [-R|--resource]
#                      [-P|--print-lines] [-O|--html-output] [-c|--conf]
#   -h|--help              : This help
#   -v|--verb              : Debug informations
#   -L|--last-minuts       : Search in the last x minuts. Default 5 min
#   -R|--resource          : Only errors from resource. Pattern matching
#   -P|--print-lines       : Print last n lines rather than number of errors
#   -O|--html-output       : add <br> tag for prettier view in Nagios Web interface
#   -c|--conf	            : Configuration file in absolut path
#
# This plugin was tested on LPAR/VIOS on Aix 6.1
#
# Versionning
# Version 1.0 : 2010/01/14
# Author : piscitelli.david@gmail.com
#
########################################################################

use strict;
use Getopt::Long;
use Data::Dumper;
use Time::Local;


#############################################################
# Global Variables
# ... I know, bad boy :p
my %ERRORS=('OK'=>0,'WARNING'=>1,'CRITICAL'=>2,'UNKNOWN'=>3);


#############################################################
# FUNCTIONS

# print help
sub help{
	print "./check_aix_errpt.pl [-h|--help] [-v|--verbose] [-L|--last-minuts] [-R|--resource] \n";
	print "                     [-P|--print-lines] [-O|--html-output] [-c|--conf]\n";
	print "  -h|--help              : This help\n";
	print "  -v|--verb              : Debug informations\n";
	print "  -L|--last-minuts       : Search in the last x minuts. Default 5 min\n";
	print "  -R|--resource          : Only errors from resource. Pattern matching\n";
	print "  -P|--print-lines       : Print last n lines rather than number of errors\n";
	print "  -O|--html-output       : add <br> tag for prettier view in Nagios Web interface\n";
	print "  -c|--conf	            : Configuration file in absolut path\n";
	exit 0;
}

# Convert a unix timestamp in ibm timestamp
# That is to say : mmddhhmmyy in errpt output
sub convert_to_ibm_time {
	my $unix_time = shift;
	my $debug = shift;
	
	my ($min,$hour,$mday,$mon,$year) = (localtime($unix_time))[1,2,3,4,5];
	#print "$min,$hour,$mday,$mon,$year\n" if $debug;
	if ( $min < 10 ){ $min = "0$min"; }
	if ( $hour < 10 ){ $hour = "0$hour"; }
	if ( $mday < 10 ){ $mday = "0$mday"; }
	$mon++;
	if ( $mon < 10 ){ $mon = "0$mon"; }
	$year = $year + 1900;
	$year =~ s/^\d{2}(\d{2})$/$1/;
	return $mon.$mday.$hour.$min.$year;
}

# Check the status of a line as defined by plugin
sub check_line {
	my $ident = shift;
	my $type = shift;
	my $class = shift;
	my $description = shift;
	my $hash_threshold = shift;
	my $debug = shift;
	
	my $identifier_check = 0;
	my $type_check = 0;
	my $class_check = 0;
	my $description_check = 0;
	my $element = "";
	
	foreach $element ( @{$hash_threshold->{IDENTIFIER}} ){
		if ( ($element eq "*") or ($element =~ m/$ident/) ){
			$identifier_check = 1;
		}
	} 
	foreach $element ( @{$hash_threshold->{TYPE}} ){
		if ( ($element eq "*") or ($element =~ m/$type/) ){
			$type_check = 1;
		}
	} 
	foreach $element ( @{$hash_threshold->{CLASS}} ){
		if ( ($element eq "*") or ($element =~ m/$class/) ){
			$class_check = 1;
		}
	} 
	foreach $element ( @{$hash_threshold->{DESCRIPTION}} ){
		if ( ($element eq "*") or ($element =~ m/$description/) ){
			$description_check = 1;
		}
	}
	return ($identifier_check and $type_check and $class_check and $description_check);
}

# Variables declaration
my $o_verb = "";
my $o_help = "";
my $o_last_minuts = 0;
my $o_warning = "";
my $o_critical = "";
my $o_resource = undef;
my $o_print_lines = 0;
my $o_html_output = 0;
# Getting line command parameters
GetOptions(
        'v'			=> \$o_verb,			'verbose'       	=> \$o_verb,
        'h'			=> \$o_help,			'help'          	=> \$o_help,
		'L:i'		=> \$o_last_minuts,		'last-minuts:i'		=> \$o_last_minuts,
		'R:s'		=> \$o_resource,		'resource:s'		=> \$o_resource,
		'P:i'		=> \$o_print_lines,		'print-lines'		=> \$o_print_lines,
		'O'			=> \$o_html_output,		'html-output'		=> \$o_html_output,	
);

##############################
# Variable declarations
my $a_line = "";
my $cmd = "";
my $cmd_return = "";
my @cmd_output = "";
my %hash_critical = ();
my %hash_warning = ();
my $i = 0;
my $ibm_timetamp_before = "";
my $ibm_timestamp_now = "";
my $is_critical_current = "";
my $is_critical_global = "";
my $is_warning_current = "";
my $is_warning_global = "";
my @list_errors = ();
my $num_errors = 0;
my $plugin_exit = "OK";
my $output = "";
my $separator = "";
my $timestamp_before = "";
my $timestamp_now = "";
my @tmp = ();

help() if ( $o_help) ;

# Default values
$o_last_minuts = 5 unless $o_last_minuts;
my $errpt = "/usr/bin/errpt";
%hash_warning = ( IDENTIFIER => ["*"],
				  TYPE => ["*"],
				  CLASS => ["H"],
				  DESCRIPTION => ["*"],
) unless %hash_warning;
%hash_critical = ( IDENTIFIER => ["*"],
				   TYPE => ["P"],
				   CLASS => ["H"],
				   DESCRIPTION => ["*"],
) unless %hash_critical;


# Convert unix timestamp in "ibm" timestamp
$timestamp_now = timelocal(localtime());
$timestamp_before = $timestamp_now - $o_last_minuts*60;
$ibm_timetamp_before = convert_to_ibm_time($timestamp_before,$o_verb);

# Launch the command
@cmd_output = `$errpt -s $ibm_timetamp_before 2>&1`;
#@cmd_output = `cat ./errpt.log`;
$cmd_return = $?>8;
if ( $cmd_return != 0 ){
	print "Error while executing cmd : $!\n";
	exit $ERRORS{UNKNOWN};
}

shift @cmd_output;
if ( scalar(@cmd_output) == 0 ){
	$output = "No new Error Reports since $ibm_timetamp_before";
	$plugin_exit = "OK";
}
else{
	$is_warning_global = 0;
	$is_critical_global = 0;
	$num_errors = 0;
	# Now we can analyse the lines
	foreach $a_line (@cmd_output){
		$is_warning_current = 0;
		$is_critical_current = 0;
		@tmp = $a_line =~ m/(\w+)\s+(\d+)\s+(\w)\s+(\w)\s+(\w+)\s+(.+)$/;
		#print "Line read = @tmp\n" if $o_verb;
		# If we have to check errors for a specific resource 
		# or all resources if not defined
		if ( not defined($o_resource) or ($tmp[4] =~ m/$o_resource/) ){
			#print "Analyse this  line\n" if $o_verb;
			# First, check warning
			$is_warning_current = check_line($tmp[0],$tmp[2],$tmp[3],$tmp[5],\%hash_warning,$o_verb);
			if ( $is_warning_current ){ 
				$is_warning_global = 1;	
				print "Line read is WARNING = @tmp\n" if $o_verb;
			}
			# And critical
			$is_critical_current = check_line($tmp[0],$tmp[2],$tmp[3],$tmp[5],\%hash_critical,$o_verb);
			if ( $is_critical_current ){ 
				$is_critical_global = 1; 
				print "Line read is CRITICAL = @tmp\n" if $o_verb;
			}
		}
		if ( $is_warning_current or $is_critical_current ){
			$num_errors++;
			push @list_errors, "$tmp[4]:$tmp[5]";
		}
	}
	print "List errors = |@list_errors|\n" if $o_verb;
	# And now, time to pay the bill...
	# Get the output...
	if ( not $o_print_lines ){
		$output = "Found $num_errors in errpt since $ibm_timetamp_before";
	}
	else {
		if ( $o_html_output ){
			$separator = "<br>";
		}
		else{
			$separator = ";";
		}
		$output = "Found ".scalar(@list_errors)." errors since $ibm_timetamp_before $separator ";
		if ( scalar(@list_errors) < $o_print_lines ) {
			for ($i=0; $i<scalar(@list_errors); $i++) {
				$output .= $list_errors[$i].$separator." ";
			}
		}
		else {
			for ($i=0; $i<$o_print_lines; $i++) {
				$output .= $list_errors[$i].$separator." ";
				#print "Output = $output\n";
			}
		}
	}
	# Get the status of the plugin
	if ( $is_critical_global ){
		$plugin_exit = "CRITICAL";
	}
	elsif ( $is_warning_global ){
		$plugin_exit = "WARNING";
	}
	else {
		$plugin_exit = "OK";
	}
}
# Out oh this plugin
print "$plugin_exit - $output\n";
exit $ERRORS{$plugin_exit};





















