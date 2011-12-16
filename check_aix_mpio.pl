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
# Plugin : check_aix_mpio.pl 
#
# Description :
# Displays information about paths to an MultiPath I/O (MPIO) capable device.
#
# Sypnosis : 
# ./check_aix_mpio.pl [-h|--help] [-v|--verbose]
#
# -h|--help              : This help
# -v|--verb              : Debug informations
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

##########################
# Functions

sub help{
	print "./check_aix_mpio.pl [-h|--help] [-v|--verbose]\n";
	print "  -h|--help              : This help\n";
	print "  -v|--verb              : Debug informations\n";
	exit 0;
}


# Variables declaration
my $a_disk = "";
my $a_connection = "";
my $a_line = "";
my $element = "";
my $cmd = "";
my $cmd_return = "";
my $cmd_output = "";
my $disk_status = "";
my @global_status_list = ();
my $is_enabled = "";
my $plugin_exit = "OK";
my $output = "";
my ($state,$disk,$connection);

my $o_verb = "";
my $o_help = "";
# Getting line command parameters
GetOptions(
        'v'		=> \$o_verb,		'verbose'       	=> \$o_verb,
        'h'		=> \$o_help,		'help'          	=> \$o_help,
);

help() if ( $o_help) ;

# Default parameters
my $lspath = "/usr/sbin/lspath";

my %hash_exit_status = ( "Enabled" 	=> "OK",
					     "Disabled"	=> "WARNING",
					     "Failed"	=> "CRITICAL",
					     "Defined"	=> "WARNING",
					     "Missing"	=> "CRITICAL",
					     "Detected"	=> "WARNING",
);

my %hash_lspath_informations = ();

# Launch the command
unless ( open CMD, "$lspath 2>&1 |" ){
	print "Error while executing \"$lspath\" : $!\n";
	exit $ERRORS{UNKNOWN};
}

# Starting to parse the output
while ( $a_line = <CMD> ){
	($state,$disk,$connection) = split /\s+/, $a_line;
	print "Disk = $disk, connection = $connection, State = $state\n" if $o_verb;
	$hash_lspath_informations{$disk}{$connection} = $state;
}
close CMD;

# Now, analyse the data
foreach $a_disk (keys %hash_lspath_informations ){
	$disk_status = "OK";
	$is_enabled = 0;
	foreach $a_connection (keys %{$hash_lspath_informations{$a_disk}} ){
		if ( $hash_lspath_informations{$a_disk}{$a_connection} ne "Enabled" ){
			# Update output
			$output .= "$a_disk on $a_connection : $hash_lspath_informations{$a_disk}{$a_connection}; "; 
			if ( $disk_status ne "CRITICAL" ){
				if ( exists($hash_exit_status{$hash_lspath_informations{$a_disk}{$a_connection}}) ){
					$disk_status = $hash_exit_status{$hash_lspath_informations{$a_disk}{$a_connection}};
				}
				else {
					$disk_status = "UNKNOWN";
				}
			}
		}
		else {
			$is_enabled = 1;
		}
	}
	# If one connection is enabled, just send warning
	if ( ($disk_status ne "OK") and $is_enabled ){
		$disk_status = "WARNING";
	}
	print "Disk $a_disk, global status : $disk_status\n" if $o_verb;
	push @global_status_list, $disk_status;
}

print "Global status List : @global_status_list\n" if $o_verb;

# Now, we need to combine the @global_status_list to define the return code of the plugin
$plugin_exit = "OK";
foreach $element (@global_status_list) {
	if ( $element ne "OK" ){
		$plugin_exit = $element;
		if ( $element eq "CRITICAL" ){
			$plugin_exit = "CRITICAL";
			last;
		} 
	}
}
if ( $plugin_exit eq "OK" ){
	$output = "All pathes are OK for all disks";
}
print "$plugin_exit - $output\n";
exit $ERRORS{$plugin_exit};















