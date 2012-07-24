#!/usr/bin/perl -w
#
# ============================== SUMMARY =====================================
#
# Program : check_catalyst_chassis.pl
# Version : 1.0
# Date    : 08/12/2011
# Authors : piscitelli.david@gmail.com
#           
# Licence : GPL - summary below, full text at http://www.fsf.org/licenses/gpl.txt
#
# =========================== PROGRAM LICENSE =================================
# check_catalyst_chassis.pl, monitor Cisco Catalyst devices
# Copyright (C) David Piscitelli
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# ===================== INFORMATIONS ABOUT THIS PLUGIN =========================
# 

#
# This plugin has been tested on  but should work on other devices
# as far they support this two MIBS
#
#
#
#
# Dependances: Net-SNMP with Net::SNMP perl library installed
#
#
#
# ======================= VERSIONS and CHANGE HISTORY =========================
# Version 1.0: Initial release
#
# ========================== START OF PROGRAM CODE ===========================
use strict;
use Net::SNMP;
use Getopt::Long;
use Data::Dumper;

# Nagios specific
our $TIMEOUT = 10;
our %ERRORS=('OK'=>0,'WARNING'=>1,'CRITICAL'=>2,'UNKNOWN'=>3);

# Version 
our $Version='1.0';

#  OIDs Indexes
my $cisco_catalyst_chassis_id 		= '.1.3.6.1.4.1.9.9.388.1.2.2.1.1';
my $cisco_catalyst_chassis_role 	= '.1.3.6.1.4.1.9.9.388.1.2.2.1.2';
my $cisco_catalyst_chassis_uptime 	= '.1.3.6.1.4.1.9.9.388.1.2.2.1.3';

# SNMPV2 Mib OIDs
my $descr_table = '.1.3.6.1.2.1.2.2.1.2';
my $admin_status = '.1.3.6.1.2.1.2.2.1.7';
my $oper_status = '1.3.6.1.2.1.2.2.1.8';
my $in_octet_table = '.1.3.6.1.2.1.2.2.1.10';
my $in_octet_table_64 = '.1.3.6.1.2.1.31.1.1.1.6';
my $out_octet_table = '.1.3.6.1.2.1.2.2.1.16';
my $out_octet_table_64 = '.1.3.6.1.2.1.31.1.1.1.10';
my $in_error_table = '1.3.6.1.2.1.2.2.1.14';
my $in_discard_table = '1.3.6.1.2.1.2.2.1.13';
my $out_error_table = '1.3.6.1.2.1.2.2.1.20';
my $out_discard_table = '1.3.6.1.2.1.2.2.1.19';
my $if_hspeed_table = '.1.3.6.1.2.1.31.1.1.1.15';
my $if_speed_table = '.1.3.6.1.2.1.2.2.1.5';

my %hash_catalyst_states = ( standalone => 1,
							 active => 2,
							 standby => 3
);
my %hash_catalyst_id_states = ( 1 => "standalone",
								2 => "active",
								3 => "standby"
);

my %hash_IfMib_states = ( 1 => {	STATE => 'up', NAGIOS_STATE => 'OK' },
						  2 => {	STATE => 'down', NAGIOS_STATE => 'CRITICAL' },
						  3 => {	STATE => 'testing', NAGIOS_STATE => 'CRITICAL' },
						  4 => {	STATE => 'unknown', NAGIOS_STATE => 'CRITICAL' },
						  5 => {	STATE => 'dormant', NAGIOS_STATE => 'CRITICAL' },
						  6 => {	STATE => 'notPresent', NAGIOS_STATE => 'CRITICAL' },
);

# Standard options
my $o_host = 		undef; 	# hostname
my $o_timeout =  	undef;  # Timeout (Default 10) 
my $o_help =		undef; 	# wan't some help ?
my $o_verb =		0;		# verbose mode
my $o_version =		undef;	# print version
my $o_warn_opt =   	undef;  # warning options
my $o_crit_opt = 	undef;  # critical options
my $o_dirstore =   undef;  
# Login and other options specific to SNMP
my $o_port =		161;    # SNMP port
my $o_octetlength =	undef;	# SNMP Message size parameter (Makina Corpus contrib)
my $o_community =	undef; 	# community
my $o_version2	=	undef;	# use snmp v2c
my $o_login =		undef;	# Login for snmpv3
my $o_passwd =		undef;	# Pass for snmpv3
my $v3protocols =	undef;	# V3 protocol list.
my $o_authproto =	'md5';	# Auth protocol
my $o_privproto =	'des';	# Priv protocol
my $o_privpass = 	undef;	# priv password
my $o_config = 		undef;
my $o_delta =		undef;
my $o_long_output	= 0;
my $o_status = 0;
my $o_interface_status = 0;
my $o_traffic = 0;
my $o_errors = 0;
my $o_discards = 0;
my $o_snmp_get = 0;
my $o_high_perf = 0;
my $o_interfaces = undef;

# Misc variables
my $output = "";
my $perfs = "";
my $exit_code = "OK";
my %hash_parse_config = ();
my $unit_coef = undef;
my $unit_string = "";
my $o_byte = 		0;
my $o_kilo = 		0;
my $o_mega = 		0;
my $o_giga = 		0;


##########################################################################
#                                                                        #    
#	FUNCTIONS                                                            #
#                                                                        #
#                                                                        #
##########################################################################

# For verbose output
sub verb { 
	my $message = shift; 
	my $verbose_level = shift;
	my $asked_verbose_level = shift;
	
	if ( $asked_verbose_level >= $verbose_level ){
		print $message."\n";
	}
}

# Create SNMP session
sub create_snmp_session {
	my ($host,$login,$passwd,$is_v2c,$port,$community,$timeout,$authproto,$privpass,$privproto,$debug) = @_;
	
	my ( $sess, $err ) = undef,undef;
	
	if ( defined($login) && defined($passwd)) {
		# SNMPv3 login
		if ( !defined ($o_privpass) ) {
			verb("SNMPv3 AuthNoPriv login : $login, $authproto",2,$debug);
			($sess, $err) = Net::SNMP->session(
							-hostname   	=> $host,
							-version		=> '3',
							-port      		=> $port,
							-username		=> $login,
							-authpassword	=> $passwd,
							-authprotocol	=> $authproto,
							-timeout        => $timeout
							);  
		} 
		else {
			verb("SNMPv3 AuthPriv login : $o_login, $o_authproto, $o_privproto",2,$debug);
			($sess, $err) = Net::SNMP->session(
							-hostname   	=> $host,
							-version		=> '3',
							-username		=> $login,
							-port      		=> $port,
							-authpassword	=> $passwd,
							-authprotocol	=> $authproto,
							-privpassword	=> $privpass,
							-privprotocol   => $privproto,
							-timeout        => $timeout
							);
		}
	} 
	elsif ( defined ($o_version2) ) {
		# SNMPv2c Login
		verb("SNMP v2c login",2,$debug);
		($sess, $err) = Net::SNMP->session(
						-hostname  => $host,
						-version   => 2,
						-community => $community,
						-port      => $port,
						-timeout   => $timeout
						);
	} 
	else {
		# SNMPV1 login
		verb("SNMP v1 login",2,$debug);
		($sess, $err) = Net::SNMP->session(
						-hostname  => $host,
						-community => $community,
						-port      => $port,
						-timeout   => $timeout
						);
	}
	return ($sess,$err);
}

sub get_table_by_id {
	my $sess = shift;
	my $base_oid = shift;
	my $debug = shift;
	
	verb("Get Index : $base_oid",2,$o_verb);
	my %hash_result = ();
	my $oid = "";
	my $resultp = $sess->get_table(Baseoid => $base_oid);
	if ( !defined($resultp) ) {
		printf("ERROR: retrieving index : %s.\n", $sess->error);
		$sess->close;
		exit $ERRORS{"UNKNOWN"};
	}
	# Create hash of VIP ids
	foreach my $key (keys %$resultp) {
		$oid = $key;
		$key =~ s/^$base_oid\.//;
		verb("=>	Oid = $oid, Id = $key, Value = $resultp->{$oid}",2,$o_verb);
		$hash_result{$key} = $resultp->{$oid};
	}
	return %hash_result;
}

# Set the session octetlength
sub fix_octet_length {
	my $snmp_sess = shift;
	my $new_value = shift;
	my $debug = shift;
	
	my $oct_result = undef;
	my $oct_test = $snmp_sess->max_msg_size();
	verb(" actual max octets:: $oct_test",2,$debug);
	$oct_result = $snmp_sess->max_msg_size($new_value);
	if ( !defined($oct_result) ) {
		 printf("ERROR: Session settings : %s.\n", $snmp_sess->error);
		 $snmp_sess->close;
		 exit $ERRORS{"UNKNOWN"};
	}
	$oct_test= $snmp_sess->max_msg_size();
	verb(" new max octets:: $oct_test",1,$debug);
}

sub p_version { print "check_snmp_netint version : $Version\n"; }

sub print_usage {
    print "Usage: $0 [-v] -H <host> (-C <snmp_community> [-2]) | (-l login -x passwd [-X pass -L <authp>,<privp>)  [-p <port>] [-w<warn levels>] [-c<crit levels>] [-o <octet_length>] [-t <timeout>] [-V] ";
	print "[-D] [-B] [-K] [-M] [-G]";
	print "[--cluster-status --config <active|standby|standalone> [--delta <n seconds>]] [--interface-status] [--errors] [--discards] [--traffic] [-n]\n";
}

# Return true if arg is a number
sub isnnum { 
	my $num = shift;
  
	if ( $num =~ /^(\d+\.?\d*)|(^\.\d+)$/ ) { 
		return 1;
	}
	else {
		return 0;
	}	
}

sub help {
   print "\nSNMP Cisco Catalyst Monitor for Nagios (check_catalyst_chassis.pl) v. ",$Version,"\n";
   print_usage();
   print <<EOT;

-v, --verbose
   print extra debugging information (including interface list on the system)
   
-h, --help
   print this help message
   
-H, --hostname=HOST
   name or IP address of host to check
   
-C, --community=COMMUNITY NAME
   community name for the SNMP agent (used with v1 or v2c protocols)
   
-2, --v2c
   use snmp v2c (can not be used with -l, -x)
   
-l, --login=LOGIN ; -x, --passwd=PASSWD
   Login and auth password for snmpv3 authentication 
   If no priv password exists, implies AuthNoPriv 
   
-X, --privpass=PASSWD
   Priv password for snmpv3 (AuthPriv protocol)
   
-L, --protocols=<authproto>,<privproto>
   <authproto> : Authentication protocol (md5|sha : default md5)
   <privproto> : Priv protocols (des|aes : default des) 
   
-p, --port=PORT
   SNMP port (Default 161)
   
-o, --octetlength=INTEGER
   max-size of the SNMP message, usefull in case of Too Long responses.
   Be carefull with network filters. Range 484 - 65535, default are
   usually 1472,1452,1460 or 1440.     
   
-w, --warning
   Warning threshold for the plugin. It could be:
	- numbers of packet drop
	- traffic defined as pourcentage of bandwith
   
-c, --critical
   Critical threshold for the plugin. It could be:
	- numbers of packet drop
	- traffic defined as pourcentage of bandwith
    
-t, --timeout=INTEGER
   timeout for SNMP in seconds (Default: 5)   
   
-V, --version
   prints version number

-D, --dir-to-store
   Directory to store history files. Default is /opt/nagios/var

-B, --byte
   By default traffic unit and thresholds are in bit/s. You can tell the plugin to use Byte instead.

-K, --kilo
   Use Kb/s or KB/s for traffic and thresholds

-M, --mega
   Use Mb/s or MB/s for traffic and thresholds

-G, --giga
   Use Gb/s or GB/s for traffic and thresholds
   
-g, --64bits
   Use 64 bits counters instead of the standard counters  
   when checking bandwidth & performance data.
   
-n, --interface
  Filter by interface name. This is a regexp
  
--cluster-status 
  Check Cluster status

--config <active|standby|standalone> 
  Use with --cluster-status. Specifie which is the nominal state of monitored host

--delta <n seconds>] 
  Interval between two nagios checks (for uptime calculation). By default five minutes

--interface-status
   Check physical interfaces

--errors
   Check errors of physical interfaces
 
--discards
   Check discards of physical interfaces

--traffic
   Check in/out traffic of physical interfaces    

EOT
}

sub push_file {
	my $file = shift;
	my $values = shift;
	
	open FILE, ">$file"
		or die "Unble to create file $file";
	my $current_date = time;
	foreach my $key (keys %$values ){
		print FILE $key.";".$current_date.";".$values->{$key}."\n";
	}
	close FILE;
}

sub get_file {
	my $file = shift;
	
	my @tmp = ();
	my %hash = ();
	my ($key,$time,$value) = (undef,undef,undef);
	
	open FILE, "<$file"
		or die "Unble to read file $file";
	while ( my $data = <FILE> ){
		($key,$time,$value) = split /;/, $data;
		$hash{$key}{TIME} = $time;
		$hash{$key}{DATA} = $value;
	}
	close FILE;
	return %hash;
}

##########################################################################
#                                                                        #    
#	MAIN PROGRAM                                                         #
#                                                                        #
#                                                                        #
##########################################################################

Getopt::Long::Configure ("bundling");
GetOptions(
 	'v:i'				=> \$o_verb,		'verbose:i'			=> \$o_verb,
    'h'     			=> \$o_help,    	'help'        		=> \$o_help,
    'H:s'   			=> \$o_host,		'hostname:s'		=> \$o_host,
    'p:i'   			=> \$o_port,   		'port:i'			=> \$o_port,
    'C:s'   			=> \$o_community,	'community:s'		=> \$o_community,
	'2'					=> \$o_version2,	'v2c'				=> \$o_version2,
	'l:s'				=> \$o_login,		'login:s'			=> \$o_login,
	'x:s'				=> \$o_passwd,		'passwd:s'			=> \$o_passwd,
	'X:s'				=> \$o_privpass,	'privpass:s'		=> \$o_privpass,
	'L:s'				=> \$v3protocols,	'protocols:s'		=> \$v3protocols,
    't:i'   			=> \$o_timeout,    	'timeout:i'			=> \$o_timeout,
	'V'					=> \$o_version,		'version'			=> \$o_version,
    'w:s'   			=> \$o_warn_opt,    'warning:s'   		=> \$o_warn_opt,
    'c:s'   			=> \$o_crit_opt,    'critical:s'   		=> \$o_crit_opt,
    'o:i'   			=> \$o_octetlength, 'octetlength:i' 	=> \$o_octetlength,
	'config:s'			=> \$o_config,
	'delta:s'			=> \$o_delta,
	'cluster-status'	=> \$o_status,
	'interface-status'	=> \$o_interface_status,
	'traffic'			=> \$o_traffic,
	'errors'			=> \$o_errors,
	'discards'			=> \$o_discards,
	'long-output'		=> \$o_long_output,
	'g'   				=> \$o_high_perf,    '64bits'   	=> \$o_high_perf,
	'n:s'				=> \$o_interfaces,
	'B'					=> \$o_byte,		'byte'				=> \$o_byte,
	'K'					=> \$o_kilo,		'kilo'				=> \$o_kilo,
	'M'					=> \$o_mega,		'mega'				=> \$o_mega,
	'G'					=> \$o_giga,		'giga'				=> \$o_giga,
);
#print "Verb : $o_verb\n";
$o_verb = 0 if not $o_verb;
if (defined ($o_help) ) { help(); exit $ERRORS{"UNKNOWN"}};
if (defined($o_version)) { p_version(); exit $ERRORS{"UNKNOWN"}};
# check snmp information
if ( !defined($o_community) && (!defined($o_login) || !defined($o_passwd)) ) { 
	print "Put snmp login info!\n"; 
	print_usage(); 
	exit $ERRORS{"UNKNOWN"};
}
if ((defined($o_login) || defined($o_passwd)) && (defined($o_community) || defined($o_version2)) ) { 
	print "Can't mix snmp v1,2c,3 protocols!\n"; 
	print_usage(); 
	exit $ERRORS{"UNKNOWN"};
}
if (defined ($v3protocols)) {
	if (!defined($o_login)) { 
		print "Put snmp V3 login info with protocols!\n"; 
		print_usage(); 
		exit $ERRORS{"UNKNOWN"};
	}
	my @v3proto=split(/,/,$v3protocols);
	if ((defined ($v3proto[0])) && ($v3proto[0] ne "")) {
		# Auth protocol
		$o_authproto = $v3proto[0];  
	}	
	if (defined ($v3proto[1])) {
		# Priv  protocol
		$o_privproto=$v3proto[1];	
	}	
	if ((defined ($v3proto[1])) && (!defined($o_privpass))) { 
		print "Put snmp V3 priv login info with priv protocols!\n"; 
		print_usage(); 
		exit $ERRORS{"UNKNOWN"};
	}
}
if (defined($o_timeout) && (isnnum($o_timeout) || ($o_timeout < 2) || ($o_timeout > 60))) { 
	print "Timeout must be >1 and <60 !\n"; 
	print_usage(); 
	exit $ERRORS{"UNKNOWN"};
}
if (!defined($o_timeout)) {$o_timeout=5;}
#### octet length checks
if (defined ($o_octetlength) && (isnnum($o_octetlength) || $o_octetlength > 65535 || $o_octetlength < 484 )) {
    print "octet length must be < 65535 and > 484\n";
	print_usage(); 
	exit $ERRORS{"UNKNOWN"};
}

# Check gobal timeout if snmp screws up
if (defined($TIMEOUT)) {
  verb("Alarm at $TIMEOUT + 5",2,$o_verb);
  alarm($TIMEOUT+5);
} 
else {
  verb("no timeout defined : $o_timeout + 10",2,$o_verb);
  alarm ($o_timeout+10);
}
$SIG{'ALRM'} = sub {
 print "No answer from host $o_host\n";
 exit $ERRORS{"UNKNOWN"};
};

# Create a new SNMP session to Alteon
my ($session,$error) = create_snmp_session($o_host,$o_login,$o_passwd,$o_version2,$o_port,$o_community,$o_timeout,$o_authproto,$o_privpass,$o_privproto,$o_verb);
if ( !defined($session) ) {
	printf("ERROR opening session: %s.\n", $error);
	exit $ERRORS{"UNKNOWN"};
}
# Set session octetlength, if necessary
if (defined($o_octetlength)) {
	my $oct_resultat=undef;
	my $oct_test=$session->max_msg_size();
	verb(" actual max octets:: $oct_test",2,$o_verb);
	$oct_resultat = $session->max_msg_size($o_octetlength);
	if (!defined($oct_resultat)) {
		 printf("ERROR: Session settings : %s.\n", $session->error);
		 $session->close;
		 exit $ERRORS{"UNKNOWN"};
	}
	$oct_test= $session->max_msg_size();
	verb(" new max octets:: $oct_test",2,$o_verb);
}

$o_interfaces = "FOO_ALL_FOO" unless $o_interfaces;
$o_dirstore = "/opt/nagios/var" unless $o_dirstore;
if ( not -d $o_dirstore."/".$o_host ){
	mkdir $o_dirstore."/".$o_host
		or die "Impossible to create ".$o_dirstore."/".$o_host." directory";
}
$o_dirstore = $o_dirstore."/".$o_host;

# Calculate the unit ratio
if ( $o_byte ){
	$unit_coef = 1;
	$unit_string = "B/s";
}
else {
	$unit_coef = 8;
	$unit_string = "b/s";
}
if ( $o_kilo ){
	$unit_coef = $unit_coef / 1024;
	$unit_string = "K".$unit_string;
}
elsif ( $o_mega ){
	$unit_coef = $unit_coef / (1024 * 1024);
	$unit_string = "M".$unit_string;
}
elsif ( $o_giga ){
	$unit_coef = $unit_coef / (1024 * 1024 * 1024);
	$unit_string = "G".$unit_string;
}
$o_delta = 300 unless $o_delta;

if ( $o_status ){
	# Fisrt, get the config
	if ($o_config ){
		my @tmp = split /,/, $o_config;
		foreach my $one (@tmp) {
			if ( $one =~ m/(\d+)\:(active|standalone|standby)/ ){
				$hash_parse_config{$1} = $2;
			}
			else {
				print "Don't understand this catalyst config : $one... should be id:<active|standby|standalone>\n";
				exit $ERRORS{UNKNOWN};
			}
		}
	}
	else {
		print "Missing --config option....\n";
		exit $ERRORS{UNKNOWN};
	}
	# Second get the real config of the device
	verb("Get Catalyst Switch Ids",1,$o_verb);
	my %hash_catalyst_ids = get_table_by_id($session,$cisco_catalyst_chassis_id,$o_verb);	
	verb("Get Catalyst Switch Roles",1,$o_verb);
	my %hash_catalyst_roles = get_table_by_id($session,$cisco_catalyst_chassis_role,$o_verb);	
	verb("Get Catalyst Switch Uptimes",1,$o_verb);
	my %hash_catalyst_uptimes = get_table_by_id($session,$cisco_catalyst_chassis_uptime,$o_verb);
	my %hash_snmp_config = ();
	foreach my $id ( keys %hash_catalyst_ids ){
		if ( exists($hash_parse_config{$hash_catalyst_ids{$id}}) ){
			# Correlate waited config et snmp config
			if ( $hash_catalyst_states{$hash_parse_config{$hash_catalyst_ids{$id}}} != $hash_catalyst_roles{$id} ){
				$output .= " Chassis ".$hash_catalyst_ids{$id}." problem: ".$hash_catalyst_id_states{$hash_catalyst_roles{$id}}." should be ".$hash_parse_config{$hash_catalyst_ids{$id}}.", ";
				$exit_code = "CRITICAL";
			}
			# Check Uptimes
			$hash_catalyst_uptimes{$id} =~ m/(\d+) days, (\d+):(\d+):(\d+)\.\d+/;
			my $uptime_sec = $1*24*3600 + $2*3600 + $3*60 +$4;
			if ( $uptime_sec <= $o_delta ){
				$output .= " Chassis ".$hash_catalyst_ids{$id}." has reboot recently : ".$hash_catalyst_uptimes{$id}.", ";
				if ( $exit_code eq "OK" ) { $exit_code = "WARNING"; }
			}	
			# Put perfs data
			$perfs .= " uptime_chassis_".$hash_catalyst_ids{$id}."=".$uptime_sec."c;;;;";
		}
	}
	if ( $exit_code eq "OK" ){
		$output = "All chassis are OK";
	}
}
elsif ( $o_interface_status ){
	# Get Interfaces by name
	verb("Get Interfaces by name",1,$o_verb);
	my %hash_interface_names = get_table_by_id($session,$descr_table,$o_verb);	
	# Get Interface Admin status
	verb("Get Interface Admin status",1,$o_verb);
	my %hash_interface_admin_status = get_table_by_id($session,$admin_status,$o_verb);	
	# Get Interface Oper status
	verb("Get Interface Oper status",1,$o_verb);
	my %hash_interface_oper_status = get_table_by_id($session,$oper_status,$o_verb);	
	foreach my $id ( keys %hash_interface_names ){
		if ( ($hash_IfMib_states{$hash_interface_admin_status{$id}}{STATE} eq "up" ) and ($o_interfaces eq "FOO_ALL_FOO" or $hash_interface_names{$id} =~ m/$o_interfaces/) ){
			verb("Check Interface: ".$hash_interface_names{$id},1,$o_verb);
			verb("	==> Admin status: ".$hash_IfMib_states{$hash_interface_admin_status{$id}}{STATE}." Oper Status: ".$hash_IfMib_states{$hash_interface_oper_status{$id}}{STATE},1,$o_verb);
			if ( $hash_IfMib_states{$hash_interface_oper_status{$id}}{NAGIOS_STATE} eq "CRITICAL" ){
				$exit_code = "CRITICAL";
				$output .= "Int(".$hash_interface_names{$id}.":".$hash_IfMib_states{$hash_interface_oper_status{$id}}{STATE}.") ";
			}
			elsif ( $hash_IfMib_states{$hash_interface_oper_status{$id}}{NAGIOS_STATE} eq "WARNING" ){
				$exit_code = "WARNING" if $exit_code eq "OK";
				$output .= " Int(".$hash_interface_names{$id}.":".$hash_IfMib_states{$hash_interface_oper_status{$id}}{STATE}.") ";
			}
		}
	}
	if ( $exit_code eq "OK" ){
		$output = "All Interfaces are UP";
	}
}
elsif ( $o_traffic ){
	my %hash_interface_names = ();
	my %hash_interface_status = ();
	my %hash_traffic_in = ();
	my %hash_traffic_out = ();
	my @ids = ();
	my $delta_time = undef;
	my $count_in = undef;
	my $count_out = undef;
	my $history_traffic_in = $o_dirstore."/catalyst_in_".$o_host;
	my $history_traffic_out = $o_dirstore."/catalyst_out_".$o_host;
	my $perf_name = "";
	my $delta_value = 0;
	my $oid_in = undef;
	my $oid_out = undef;
	my $max_bits;
	my $crit = undef;
	my $warn = undef;
	if ( $o_high_perf ){
		$oid_in = $in_octet_table_64;
		$oid_out = $out_octet_table_64;
		$max_bits = 18446744073709551616;
	}
	else {
		$oid_in = $in_octet_table;
		$oid_out = $out_octet_table;
		$max_bits = 4294967296;
	}
	# Get Interfaces by name
	verb("Get Interfaces by name, snmpgettable method",1,$o_verb);
	%hash_interface_names = get_table_by_id($session,$descr_table,$o_verb);	
	# Get Interface status
	verb("Get Interface status, snmpgettable method",1,$o_verb);
	%hash_interface_status = get_table_by_id($session,$oper_status,$o_verb);	
	verb("Get Traffic IN, snmpgettable method",1,$o_verb);
	%hash_traffic_in = get_table_by_id($session,$oid_in,$o_verb);
	verb("Get Traffic OUT, snmpgettable method",1,$o_verb);
	%hash_traffic_out = get_table_by_id($session,$oid_out,$o_verb);
	my %hash_if_speed = ();
	my $speed_table_coef = undef;
	if ( $o_crit_opt or $o_warn_opt ){
		if ( $o_version2 or $v3protocols ){
			verb("Get High IF-MIB Speed Table",1,$o_verb);
			%hash_if_speed = get_table_by_id($session,$if_hspeed_table,$o_verb);
			$speed_table_coef = 1000000;
		}
		else {
			%hash_if_speed = get_table_by_id($session,$if_speed_table,$o_verb);
			$speed_table_coef = 1;
		}
	}
	if ( -s $history_traffic_in and -s $history_traffic_out ){
		# We have history, it can work
		my %hash_traffic_in_old = get_file($history_traffic_in);
		my %hash_traffic_out_old = get_file($history_traffic_out);
		foreach my $id ( keys %hash_interface_names ){
			verb("Interface Id=".$id." Name= ".$hash_interface_names{$id}."- Old IN: ".$hash_traffic_in_old{$id}{DATA}." New IN: ".$hash_traffic_in{$id},3,$o_verb);
			verb("Interface Id=".$id." Name= ".$hash_interface_names{$id}."- Old OUT: ".$hash_traffic_out_old{$id}{DATA}." New OUT: ".$hash_traffic_out{$id},3,$o_verb);
			if ( ($hash_interface_status{$id} == 1 ) and ($hash_interface_names{$id} =~ m/Ethernet/) and ($o_interfaces eq "FOO_ALL_FOO" or $hash_interface_names{$id} =~ m/$o_interfaces/) ){
				$perf_name = $hash_interface_names{$id};
				# We need to format Output for performance data to fit with 4096 octets Nagios limit
				$perf_name =~ s/GigabitEthernet/GbEth/;
				$perf_name =~ s/TenGigabitEthernet/TenGbEth/;
				$perf_name =~ s/\s+/_/g;
				verb("Check Interface: Id=".$id." ".$perf_name." ==> ".$hash_interface_names{$id},3,$o_verb);
				$delta_time = time - $hash_traffic_in_old{$id}{TIME};
				if ( $hash_traffic_in{$id} >= $hash_traffic_in_old{$id}{DATA} ){
					$delta_value = $hash_traffic_in{$id} - $hash_traffic_in_old{$id}{DATA};
				}
				else {
					$delta_value = $max_bits - $hash_traffic_in_old{$id}{DATA} + $hash_traffic_in{$id};
				}
				$count_in = $delta_value / $delta_time  * $unit_coef;
				$count_in = sprintf "%.2f", $count_in;
				if ( $hash_traffic_out{$id} >= $hash_traffic_out_old{$id}{DATA} ){
					$delta_value = $hash_traffic_out{$id} - $hash_traffic_out_old{$id}{DATA};
				}
				else {
					$delta_value = $max_bits - $hash_traffic_out_old{$id}{DATA} + $hash_traffic_out{$id};
				}
				$count_out =  $delta_value / $delta_time  * $unit_coef;
				$count_out = sprintf "%.2f", $count_out;
				$perfs .= " 'in_".$perf_name."'=".$count_in.$unit_string." 'out_".$perf_name."'=".$count_out.$unit_string;
				if ( $o_crit_opt ) {
					$crit = $o_crit_opt / 100 * $hash_if_speed{$id} * $unit_coef / 8 * $speed_table_coef;
				}
				if ( $o_warn_opt ) {
					$warn = $o_warn_opt / 100 * $hash_if_speed{$id} * $unit_coef / 8 * $speed_table_coef;
				}
				verb($hash_interface_names{$id}." Crit threshold:".$crit.", Warn threshold:".$warn,1,$o_verb); 
				if ( $o_crit_opt and ( ($count_in >= $crit) or ($count_out >= $crit)) ) {
					$exit_code = "CRITICAL";
					$output .= "traffic port ".$hash_interface_names{$id}." (IN:".$count_in.$unit_string." OUT:".$count_out.$unit_string."); ";
				}
				elsif ( $o_warn_opt and (($count_in >= $warn) or ($count_out >= $warn)) ) {
					$exit_code = "WARNING" if $exit_code eq "OK";
					$output .= "traffic port ".$hash_interface_names{$id}." (IN:".$count_in.$unit_string." OUT:".$count_out.$unit_string."); ";
				}
			}
		}
		if ( $exit_code eq "OK" ){
			$output = "Traffic OK";
		}
	}
	else {
		# no data, put the current data in history files and get stuff next time
		$exit_code = "OK";
		$output = "NO USABLE DATA, maybe next time";
	}
	# Finally push new values
	push_file($history_traffic_in, \%hash_traffic_in);
	push_file($history_traffic_out, \%hash_traffic_out);	
}
elsif ( $o_errors ){
	my %hash_interface_names = ();
	my %hash_interface_status = ();
	my %hash_errors_in = ();
	my %hash_errors_out = ();
	my @ids = ();
	my $delta_time = undef;
	my $errors_in = undef;
	my $errors_out = undef;
	my $history_errors_in = $o_dirstore."/catalyst_errors_in_".$o_host;
	my $history_errors_out = $o_dirstore."/catalyst_errors_out_".$o_host;
	my $perf_name = "";
	my $delta_value = 0;
	# Get Interfaces by name
	verb("Get Interfaces by name, snmpgettable method",1,$o_verb);
	%hash_interface_names = get_table_by_id($session,$descr_table,$o_verb);	
	# Get Interface status
	verb("Get Interface status, snmpgettable method",1,$o_verb);
	%hash_interface_status = get_table_by_id($session,$oper_status,$o_verb);	
	verb("Get Packet Errors In, snmpgettable method",1,$o_verb);
	%hash_errors_in = get_table_by_id($session,$in_error_table,$o_verb);
	verb("Get Packet Errors Out, snmpgettable method",1,$o_verb);
	%hash_errors_out = get_table_by_id($session,$out_error_table,$o_verb);
	if ( -s $history_errors_in and -s $history_errors_out){
		# We have history, it can work
		my %hash_errors_in_old = get_file($history_errors_in);
		my %hash_errors_out_old = get_file($history_errors_out);
		foreach my $id ( keys %hash_interface_names ){
			if ( ($hash_interface_status{$id} == 1 ) and ($hash_interface_names{$id} =~ m/Ethernet/) and ($o_interfaces eq "FOO_ALL_FOO" or $hash_interface_names{$id} =~ m/$o_interfaces/) ){	
				$perf_name = $hash_interface_names{$id};
				# We need to format Output for performance data to fit with 4096 octets Nagios limit
				$perf_name =~ s/GigabitEthernet/GbEth/;
				$perf_name =~ s/TenGigabitEthernet/TenGbEth/;
				$perf_name =~ s/\s+/_/g;
				verb("Check Interface: Id=".$id." ".$perf_name." ==> ".$hash_interface_names{$id},3,$o_verb);
				verb("Check Interface: status: ".$hash_interface_status{$id},3,$o_verb);
				verb("Check Interface: Errors_in: ".$hash_errors_in{$id},3,$o_verb);
				verb("Check Interface: Errors_out: ".$hash_errors_out{$id},3,$o_verb);
				$delta_time = time - $hash_errors_in_old{$id}{TIME};
				$errors_in = sprintf "%.2f",  ( ($hash_errors_in{$id} - $hash_errors_in_old{$id}{DATA}) / $delta_time );
				$errors_out = sprintf "%.2f",  ( ($hash_errors_out{$id} - $hash_errors_out_old{$id}{DATA}) / $delta_time );
				# Formating output
				$perfs .= " 'err_in_".$perf_name."'=".$errors_in."/s 'err_out_".$perf_name."'=".$errors_out."/s";
				if ( $o_crit_opt and ( ($errors_in >= $o_crit_opt) or ($errors_out >= $o_crit_opt)) ) {
					$exit_code = "CRITICAL";
					$output .= $hash_interface_names{$id}.": CRITICAL - Errors(".$errors_in."ps/".$errors_out."ps); ";
				}
				elsif ( $o_warn_opt and (($errors_in >= $o_warn_opt) or ($errors_out >= $o_warn_opt)) ) {
					$exit_code = "WARNING" if $exit_code eq "OK";
					$output .= $hash_interface_names{$id}.": WARNING - Errors(".$errors_in."ps/".$errors_out."ps); ";
				}
				elsif ( $o_long_output ) {
					$output .= $hash_interface_names{$id}.": OK - Errors(".$errors_in."ps/".$errors_out."ps); ";
				}
			}
		}
		if ( not $o_long_output and ($exit_code eq "OK") ){
			$output = "No problem detected for Errors";
		}
	}
	else {
		# no data, put the current data in history files and get stuff next time
		$exit_code = "OK";
		$output = "NO USABLE DATA, maybe next time";
	}
	# Finally push new values
	push_file($history_errors_in, \%hash_errors_in);
	push_file($history_errors_out, \%hash_errors_out);
}
elsif ( $o_discards ){
	my %hash_interface_names = ();
	my %hash_interface_status = ();
	my %hash_discards_in = ();
	my %hash_discards_out = ();
	my @ids = ();
	my $delta_time = undef;
	my $discards_in = undef;
	my $discards_out = undef;
	my $history_discards_in = $o_dirstore."/catalyst_discards_in_".$o_host;
	my $history_discards_out = $o_dirstore."/catalyst_discards_out_".$o_host;
	my $perf_name = "";
	my $delta_value = 0;
	# Get Interfaces by name
	verb("Get Interfaces by name, snmpgettable method",1,$o_verb);
	%hash_interface_names = get_table_by_id($session,$descr_table,$o_verb);	
	# Get Interface status
	verb("Get Interface status, snmpgettable method",1,$o_verb);
	%hash_interface_status = get_table_by_id($session,$oper_status,$o_verb);	
	verb("Get Packet Discards In, snmpgettable method",1,$o_verb);
	%hash_discards_in = get_table_by_id($session,$in_discard_table,$o_verb);
	verb("Get Packet Discards Out, snmpgettable method",1,$o_verb);
	%hash_discards_out = get_table_by_id($session,$out_discard_table,$o_verb);
	if ( -s $history_discards_in and -s $history_discards_out){
		# We have history, it can work
		my %hash_discards_in_old = get_file($history_discards_in);
		my %hash_discards_out_old = get_file($history_discards_out);
		foreach my $id ( keys %hash_interface_names ){
			if ( ($hash_interface_status{$id} == 1 ) and ($hash_interface_names{$id} =~ m/Ethernet/) and ($o_interfaces eq "FOO_ALL_FOO" or $hash_interface_names{$id} =~ m/$o_interfaces/) ){	
				$perf_name = $hash_interface_names{$id};
				# We need to format Output for performance data to fit with 4096 octets Nagios limit
				$perf_name =~ s/GigabitEthernet/GbEth/;
				$perf_name =~ s/TenGigabitEthernet/TenGbEth/;
				$perf_name =~ s/\s+/_/g;
				verb("Check Interface: ".$perf_name." ==> ".$hash_interface_names{$id},3,$o_verb);
				
				$delta_time = time - $hash_discards_in_old{$id}{TIME};
				$discards_in = sprintf "%.2f",  ( ($hash_discards_in{$id} - $hash_discards_in_old{$id}{DATA}) / $delta_time );
				$discards_out = sprintf "%.2f",  ( ($hash_discards_out{$id} - $hash_discards_out_old{$id}{DATA}) / $delta_time );
				# Formating output
				$perfs .= " 'disc_in_".$perf_name."'=".$discards_in."/s 'disc_out_".$perf_name."'=".$discards_out."/s";
				if ( $o_crit_opt and ( ($discards_in >= $o_crit_opt) or ($discards_out >= $o_crit_opt)) ) {
					$exit_code = "CRITICAL";
					$output .= $hash_interface_names{$id}.": CRITICAL - Discards(".$discards_in."ps/".$discards_out."ps); ";
				}
				elsif ( $o_warn_opt and (($discards_in >= $o_warn_opt) or ($discards_out >= $o_warn_opt)) ) {
					$exit_code = "WARNING" if $exit_code eq "OK";
					$output .= $hash_interface_names{$id}.": WARNING - Discards(".$discards_in."ps/".$discards_out."ps); ";
				}
				elsif ( $o_long_output ) {
					$output .= $hash_interface_names{$id}.": OK - Discards(".$discards_in."ps/".$discards_out."ps); ";
				}
			}
		}
		if ( not $o_long_output and ($exit_code eq "OK") ){
			$output = "No problem detected for Discards";
		}
	}
	else {
		# no data, put the current data in history files and get stuff next time
		$exit_code = "OK";
		$output = "NO USABLE DATA, maybe next time";
	}
	# Finally push new values
	push_file($history_discards_in, \%hash_discards_in);
	push_file($history_discards_out, \%hash_discards_out);
}
print "$exit_code - $output | $perfs\n";
exit $ERRORS{$exit_code};


