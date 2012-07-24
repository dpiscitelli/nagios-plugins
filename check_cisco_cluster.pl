#!/usr/bin/perl -w
#
# ============================== SUMMARY =====================================
#
# Program : check_cisco_cluster.pl
# Version : 1.0
# Date    : 2011/12/15
# Authors : piscitelli.david@gmail.com
#           
# Licence : GPL - summary below, full text at http://www.fsf.org/licenses/gpl.txt
#
# =========================== PROGRAM LICENSE =================================
# check_cisco_cluster.pl, monitor Cisco Cluster FW
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
my $cfwHardwareStatusTable 	= '.1.3.6.1.4.1.9.9.147.1.2.1.1';

# SNMPV2 Mib OIDs
my $descr_table = '.1.3.6.1.2.1.2.2.1.2';
my $admin_status = '.1.3.6.1.2.1.2.2.1.7';
my $in_octet_table = '.1.3.6.1.2.1.2.2.1.10';
my $in_octet_table_64 = '.1.3.6.1.2.1.31.1.1.1.6';
my $out_octet_table = '.1.3.6.1.2.1.2.2.1.16';
my $out_octet_table_64 = '.1.3.6.1.2.1.31.1.1.1.10';
my $in_error_table = '1.3.6.1.2.1.2.2.1.14';
my $in_discard_table = '1.3.6.1.2.1.2.2.1.13';
my $out_error_table = '1.3.6.1.2.1.2.2.1.20';
my $out_discard_table = '1.3.6.1.2.1.2.2.1.19';
my $if_speed_table = '.1.3.6.1.2.1.2.2.1.5';

my %hash_cfwHardwareType = ( 1 => 'memory',		
							 2 => 'disk',
							 3 => 'power',
							 4 => 'netInterface',
							 5 => 'cpu',
							 6 => 'primaryUnit',
							 7 => 'secondaryUnit',
							 8 => 'other',
);

my %hash_cfwHardwareStatusValue = ( 1 => {	STATE => 'other', NAGIOS_STATE => 'WARNING' },
									2 => {	STATE => 'up', NAGIOS_STATE => 'OK' },
									3 => {	STATE => 'down', NAGIOS_STATE => 'CRITICAL' },
									4 => {	STATE => 'error', NAGIOS_STATE => 'CRITICAL' },
									5 => {	STATE => 'overTemp', NAGIOS_STATE => 'CRITICAL' },
									6 => {	STATE => 'busy', NAGIOS_STATE => 'WARNING' },
									7 => {	STATE => 'noMedia', NAGIOS_STATE => 'WARNING' },
									8 => {	STATE => 'backup', NAGIOS_STATE => 'OK' },
									9 => {	STATE => 'active', NAGIOS_STATE => 'OK' },
									10 => {	STATE => 'standby', NAGIOS_STATE => 'OK' },
);									

# Standard options
my $o_host 			= undef; 	# hostname
my $o_timeout 		= undef;  # Timeout (Default 10) 
my $o_help 			= undef; 	# wan't some help ?
my $o_verb 			= 0;		# verbose mode
my $o_version 		= undef;	# print version
my $o_warn_opt 		= undef;  # warning options
my $o_crit_opt 		= undef;  # critical options
my $o_dirstore 		= undef;  

# Misc Options
my $o_byte = 		0;
my $o_kilo = 		0;
my $o_mega = 		0;
my $o_giga = 		0;

# Login and other options specific to SNMP
my $o_port 			= 161;    # SNMP port
my $o_octetlength 	= undef;	# SNMP Message size parameter (Makina Corpus contrib)
my $o_community 	= undef; 	# community
my $o_version2		= undef;	# use snmp v2c
my $o_login 		= undef;	# Login for snmpv3
my $o_passwd 		= undef;	# Pass for snmpv3
my $v3protocols 	= undef;	# V3 protocol list.
my $o_authproto 	= 'md5';	# Auth protocol
my $o_privproto 	= 'des';	# Priv protocol
my $o_privpass 		= undef;	# priv password
my $o_check_all 	= 0;
my $o_long_output	= 0;
my $o_status = 0;
my $o_traffic = 0;
my $o_errors = 0;
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

sub get_snmp_by_id {
	my $sess = shift;
	my $base_oid = shift;
	my $ids = shift;
	my $debug = shift;
	
	verb("Get Index : $base_oid",2,$o_verb);
	my %hash_result = ();
	my $oid = "";
	my $resultp = undef;
	my @oids = ();
	@oids = map { $base_oid.".".$_ } @$ids;
	verb("OID list : @oids",2,$o_verb);
	$resultp = $sess->get_request(-varbindlist => \@oids);
	if ( !defined($resultp) ) {
		printf("ERROR: retrieving OID: %s.\n", $sess->error);
		$sess->close;
		exit $ERRORS{"UNKNOWN"};
	}
	#Create hash of VIP ids
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
	print "[-D] [-B] [-K] [-M] [-G] [--list] [--exclude] [--long-output] [--if-speed]";
	print "[--status [--check-all]] [--errors] [--traffic]\n";
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
   print "\nSNMP Alteon Monitor for Nagios (check_cisco_cluster.pl) v. ",$Version,"\n";
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
	- count
	- numbers of errors/discards
	- traffic
   
-c, --critical
   Critical threshold for the plugin. It could be:
	- count
	- number of errors/discards
	- traffic
    
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

--status
   Check state of devices. By default only "unit" devices are monitored

--check-all
   Check all devices even NetInterfaces,memory,disk,power,...

--errors
   Check errors/discards of physical interfaces

--traffic
   Check in/out traffic of physical interfaces    

--long-output
   Print detailed plugin output

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


sub get_id_list_to_check {
	my $list = shift;
	my $exclude = shift;
	my $desc = shift;
	my $addr = shift;
	my $debug = shift;
	
	my %hash = ();
	my %hash_exclude = ();
	
	my @tmp = split /,/, $list;
	if ( $tmp[0] eq "ALL" ){
		if ( $exclude ){
			my @tmp2 = split /,/, $exclude;
			%hash_exclude = map { $_ => 1 } @tmp2;
		}
		foreach my $id (keys %$addr){
			if ( $desc->{$id} and not $hash_exclude{$desc->{$id}} ) {
				$hash{$id} = $desc->{$id} || $addr->{$id};
			}
			elsif ( not $hash_exclude{$addr->{$id}} ) {
				$hash{$id} = $addr->{$id};
			}
		}
	}
	else {
		foreach my $element (@tmp) {
			my $found = 0;
			foreach my $id (keys %$addr){
				#print "$element, $desc->{$id}, $addr->{$id}\n";
				if ( $desc->{$id} and ($element eq $desc->{$id}) ){
					$hash{$id} = $desc->{$id};
					$found = 1;
				}
				elsif ( $element eq $addr->{$id} ){
					$hash{$id} = $addr->{$id};
					$found = 1;
				}
			}	
			if ( not $found ){
				print "Unknown interface : $element\n";
				exit $ERRORS{"UNKNOWN"};
			}
		}
	}
	return %hash;
}

sub get_port_list_to_check {
	my $list = shift;
	my $exclude = shift;
	my $all_ports = shift;
	my $debug = shift;
	
	my @return_list = ();
	my %hash_exclude = ();
	
	my @tmp = split /,/, $list;
	if ( $tmp[0] eq "ALL" ){
		if ( $exclude ){
			my @tmp2 = split /,/, $exclude;
			%hash_exclude = map { $_ => 1 } @tmp2;
		}
		foreach my $port ( keys %$all_ports ){
			if ( not $hash_exclude{$port} ) {
				 push @return_list, $port;
			}
		}
	}
	else {
		foreach my $element (@tmp) {
			my $found = 0;
			foreach my $port (keys %$all_ports){
				if ( $element eq $port ){
					push @return_list, $port;
					$found = 1;
				}
			}	
			if ( not $found ){
				print "Unknown port : $element\n";
				exit $ERRORS{"UNKNOWN"};
			}
		}
	}
	return @return_list;
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
	'status'			=> \$o_status,
	'traffic'			=> \$o_traffic,
	'errors'			=> \$o_errors,
	'check-all'			=> \$o_check_all,
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
$o_interfaces = "FOO_ALL_FOO" unless $o_interfaces;
$o_dirstore = "/opt/nagios/var" unless $o_dirstore;
if ( not -d $o_dirstore."/".$o_host ){
	mkdir $o_dirstore."/".$o_host
		or die "Impossible to create ".$o_dirstore."/".$o_host." directory";
}
$o_dirstore = $o_dirstore."/".$o_host;

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

# First get informations of the cluster units
if ( $o_status ){
	verb("Get All Informations",1,$o_verb);
	my %hash_infos_all = get_table_by_id($session,$cfwHardwareStatusTable,$o_verb);	
	my %hash_infos_sort = ();
	my $id_root = undef;
	my $id_type = undef;
	my $id_info_snmp = undef;
	foreach my $id (keys %hash_infos_all ){
		$id =~ m/(\d+)\.(\d+)\.(\d+)/;
		$id_root = $1;
		$id_info_snmp = $2;
		$id_type = $3;
		$hash_infos_sort{$id_root}{$id_type}{$id_info_snmp} = $hash_infos_all{$id};
	}
	# Now, make the job
	foreach $id_root (sort keys %hash_infos_sort ){
		foreach $id_type (sort keys %{$hash_infos_sort{$id_root}}){
			verb("ID root: ".$id_root.", Type: ".$hash_cfwHardwareType{$id_type}.", Info: ".$hash_infos_sort{$id_root}{$id_type}{2}.", Status: ".$hash_cfwHardwareStatusValue{$hash_infos_sort{$id_root}{$id_type}{3}}{STATE}.", Status Detail: ".$hash_infos_sort{$id_root}{$id_type}{4},2,$o_verb);
			if ( ($hash_cfwHardwareType{$id_type} eq "primaryUnit") and ($hash_cfwHardwareStatusValue{$hash_infos_sort{$id_root}{$id_type}{3}}{STATE} ne "active") ){
				# Push information to output, if this is "this device"
				if ( $hash_infos_sort{$id_root}{$id_type}{2} =~ m/\(this device\)/ ){
					$output .= "This device (".$hash_cfwHardwareType{$id_type}.") is ".$hash_cfwHardwareStatusValue{$hash_infos_sort{$id_root}{$id_type}{3}}{STATE}."; ";
					$exit_code = "CRITICAL";
				}
			}
			elsif ( ($hash_cfwHardwareType{$id_type} eq "secondaryUnit") and ($hash_cfwHardwareStatusValue{$hash_infos_sort{$id_root}{$id_type}{3}}{STATE} ne "standby") ){
				# Push information to output, if this is "this device"
				if ( $hash_infos_sort{$id_root}{$id_type}{2} =~ m/\(this device\)/){
					$output .= "This device (".$hash_cfwHardwareType{$id_type}.") is ".$hash_cfwHardwareStatusValue{$hash_infos_sort{$id_root}{$id_type}{3}}{STATE}."; ";
					$exit_code = "CRITICAL";
				}
			}
			elsif ( $o_check_all ) {
				# This is another kind of hardware, check it
				if ( $hash_cfwHardwareStatusValue{$hash_infos_sort{$id_root}{$id_type}{3}}{NAGIOS_STATE} ne "OK" ){
					if ( $exit_code eq "OK" ){ 
						$exit_code = $hash_cfwHardwareStatusValue{$hash_infos_sort{$id_root}{$id_type}{3}}{NAGIOS_STATE};
					}
					elsif ($exit_code eq "WARNING" ){ 
						$exit_code = $hash_cfwHardwareStatusValue{$hash_infos_sort{$id_root}{$id_type}{3}}{NAGIOS_STATE}; 
					}
					$output .= "Device (".$hash_cfwHardwareType{$id_type}.") is ".$hash_cfwHardwareStatusValue{$hash_infos_sort{$id_root}{$id_type}{3}}{STATE}."; ";
				}
				elsif ( $o_long_output ) {
					$output .= "Device (".$hash_cfwHardwareType{$id_type}.") is ".$hash_cfwHardwareStatusValue{$hash_infos_sort{$id_root}{$id_type}{3}}{STATE}."; ";
				}
			}
			elsif ( $o_long_output ) {
				$output .= "Device (".$hash_cfwHardwareType{$id_type}.") is ".$hash_cfwHardwareStatusValue{$hash_infos_sort{$id_root}{$id_type}{3}}{STATE}."; ";
			}
		}
	}
	if ( $exit_code eq "OK" and not $o_long_output ){
		$output = "All Units are OK";
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
	my $history_traffic_in = $o_dirstore."/cisco_in_".$o_host;
	my $history_traffic_out = $o_dirstore."/cisco_out_".$o_host;
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
	%hash_interface_status = get_table_by_id($session,$admin_status,$o_verb);	
	verb("Get Traffic IN, snmpgettable method",1,$o_verb);
	%hash_traffic_in = get_table_by_id($session,$oid_in,$o_verb);
	verb("Get Traffic OUT, snmpgettable method",1,$o_verb);
	%hash_traffic_out = get_table_by_id($session,$oid_out,$o_verb);
	my %hash_if_speed = ();
	if ( $o_crit_opt or $o_warn_opt ){
		verb("Get IF-MIB Speed Table",1,$o_verb);
		%hash_if_speed = get_table_by_id($session,$if_speed_table,$o_verb);
	}
	if ( -s $history_traffic_in and -s $history_traffic_out ){
		# We have history, it can work
		my %hash_traffic_in_old = get_file($history_traffic_in);
		my %hash_traffic_out_old = get_file($history_traffic_out);
		foreach my $id ( keys %hash_interface_names ){
			verb("Interface Id=".$id." Name= ".$hash_interface_names{$id}."- Old IN: ".$hash_traffic_in_old{$id}{DATA}." New IN: ".$hash_traffic_in{$id},3,$o_verb);
			verb("Interface Id=".$id." Name= ".$hash_interface_names{$id}."- Old OUT: ".$hash_traffic_out_old{$id}{DATA}." New OUT: ".$hash_traffic_out{$id},3,$o_verb);
			if ( $o_interfaces eq "FOO_ALL_FOO" or $hash_interface_names{$id} =~ m/$o_interfaces/ ){
				$perf_name = $hash_interface_names{$id};
				# We need to format Output for performance data
				if ( $perf_name =~m/'(.+?)'/ ){
					$perf_name = $1;
				}
				$perf_name =~ s/\s+/_/g;
				verb("Check Interface: ".$perf_name." ==> ".$hash_interface_names{$id},3,$o_verb);
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
				$perfs .= " 'in_".$perf_name."'=".$count_in.$unit_string.";;;; 'out_".$perf_name."'=".$count_out.$unit_string.";;;;";
				# Fix thresholds to have them in pourcentages of bandwith
				if ( $o_crit_opt ) {
					$crit = $o_crit_opt / 100 * $hash_if_speed{$id} * $unit_coef / 8;
					#print "$o_crit_opt $hash_if_speed{$id} $unit_coef\n";
				}
				if ( $o_warn_opt ) {
					$warn = $o_warn_opt / 100 * $hash_if_speed{$id} * $unit_coef / 8;
				}
				verb("Crit threshold:".$crit.", Warn threshold:".$warn,1,$o_verb); 
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
	my %hash_discards_in = ();
	my %hash_errors_out = ();
	my %hash_discards_out = ();
	my @ids = ();
	my $delta_time = undef;
	my $errors_in = undef;
	my $discards_in = undef;
	my $errors_out = undef;
	my $discards_out = undef;
	my $history_errors_in = $o_dirstore."/cisco_errors_in".$o_host;
	my $history_discards_in = $o_dirstore."/cisco_discards_in".$o_host;
	my $history_errors_out = $o_dirstore."/cisco_errors_out".$o_host;
	my $history_discards_out = $o_dirstore."/cisco_discards_out".$o_host;
	my $perf_name = "";
	my $delta_value = 0;
	# Fix thresholds
	my ($o_crit_opt_err,$o_crit_opt_disc) = (1000000,1000000);
	my ($o_warn_opt_err,$o_warn_opt_disc) = (1000000,1000000);
	if ( $o_crit_opt ){
		($o_crit_opt_err,$o_crit_opt_disc) = split /,/, $o_crit_opt;
	}
	if ( $o_warn_opt ){
		($o_warn_opt_err,$o_warn_opt_disc) = split /,/, $o_warn_opt;
	}
	verb("Crit err/disc: $o_crit_opt_err,$o_crit_opt_disc - Warn err/disc: $o_warn_opt_err,$o_warn_opt_disc",1,$o_verb);
	# Get Interfaces by name
	verb("Get Interfaces by name, snmpgettable method",1,$o_verb);
	%hash_interface_names = get_table_by_id($session,$descr_table,$o_verb);	
	# Get Interface status
	verb("Get Interface status, snmpgettable method",1,$o_verb);
	%hash_interface_status = get_table_by_id($session,$admin_status,$o_verb);	
	verb("Get Packet Errors In, snmpgettable method",1,$o_verb);
	%hash_errors_in = get_table_by_id($session,$in_error_table,$o_verb);
	verb("Get Packet Discards In, snmpgettable method",1,$o_verb);
	%hash_discards_in = get_table_by_id($session,$in_discard_table,$o_verb);
	verb("Get Packet Errors Out, snmpgettable method",1,$o_verb);
	%hash_errors_out = get_table_by_id($session,$out_error_table,$o_verb);
	verb("Get Packet Discards Out, snmpgettable method",1,$o_verb);
	%hash_discards_out = get_table_by_id($session,$out_discard_table,$o_verb);
	if ( -s $history_errors_in and -s $history_discards_in and -s $history_errors_out and -s $history_discards_out){
		# We have history, it can work
		my %hash_errors_in_old = get_file($history_errors_in);
		my %hash_errors_out_old = get_file($history_errors_out);
		my %hash_discards_in_old = get_file($history_discards_in);
		my %hash_discards_out_old = get_file($history_discards_out);
		foreach my $id ( keys %hash_interface_names ){
			if ( $o_interfaces eq "FOO_ALL_FOO" or $hash_interface_names{$id} =~ m/$o_interfaces/ ){	
				$perf_name = $hash_interface_names{$id};
				# We need to format Output for performance data
				if ( $perf_name =~m/'(.+?)'/ ){
					$perf_name = $1;
				}
				$perf_name =~ s/\s+/_/g;
				verb("Check Interface: ".$perf_name." ==> ".$hash_interface_names{$id},3,$o_verb);
				$delta_time = time - $hash_errors_in_old{$id}{TIME};
				$errors_in = sprintf "%.2f",  ( ($hash_errors_in{$id} - $hash_errors_in_old{$id}{DATA}) / $delta_time );
				$errors_out = sprintf "%.2f",  ( ($hash_errors_out{$id} - $hash_errors_out_old{$id}{DATA}) / $delta_time );
				$discards_in = sprintf "%.2f",  ( ($hash_discards_in{$id} - $hash_discards_in_old{$id}{DATA}) / $delta_time );
				$discards_out = sprintf "%.2f",  ( ($hash_discards_out{$id} - $hash_discards_out_old{$id}{DATA}) / $delta_time );
				# Formating output
				$perfs .= " 'err_in_".$perf_name."'=".$errors_in."/s 'err_out_".$perf_name."'=".$errors_out."/s";
				$perfs .= " 'disc_in_".$perf_name."'=".$discards_in."/s 'disc_out_".$perf_name."'=".$discards_out."/s";
				if ( $o_crit_opt and ( ($errors_in >= $o_crit_opt_err) or ($errors_out >= $o_crit_opt_err) or ($discards_in >= $o_crit_opt_disc) or ($discards_out >= $o_crit_opt_disc)) ) {
					$exit_code = "CRITICAL";
					$output .= $hash_interface_names{$id}.": CRITICAL - Errors(".$errors_in."ps/".$errors_out."ps) Discards(".$discards_in."ps/".$discards_out."ps); ";
				}
				elsif ( $o_warn_opt and (($errors_in >= $o_warn_opt_err) or ($errors_out >= $o_warn_opt_err) or ($discards_in >= $o_warn_opt_disc) or ($discards_out >= $o_warn_opt_disc)) ) {
					$exit_code = "WARNING" if $exit_code eq "OK";
					$output .= $hash_interface_names{$id}.": Errors(".$errors_in."ps/".$errors_out."ps) Discards(".$discards_in."ps/".$discards_out."ps); ";
				}
				elsif ( $o_long_output ) {
					$output .= $hash_interface_names{$id}.": WARNING - Errors(".$errors_in."ps/".$errors_out."ps) Discards(".$discards_in."ps/".$discards_out."ps); ";
				}
			}
		}
		if ( not $o_long_output and ($exit_code eq "OK") ){
			$output = "Errors/Discards OK";
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
	push_file($history_discards_in, \%hash_discards_in);
	push_file($history_discards_out, \%hash_discards_out);
}
print "$exit_code - $output | $perfs\n";
exit $ERRORS{$exit_code};


