#!/usr/bin/perl -w
#
# ============================== SUMMARY =====================================
#
# Program : check_alteon.pl
# Version : 1.0
# Date    : 10/11/2011
# Authors : piscitelli.david@gmail.com
#           
# Licence : GPL - summary below, full text at http://www.fsf.org/licenses/gpl.txt
#
# =========================== PROGRAM LICENSE =================================
# check_alteon.pl, monitor alteon devices
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
# This Nagios plugin checks the Alteon's virual Servers.
# It can retrieve :
# 1) Sessions stats by VIP or by RIP
# 2) The states of Real Servers versus VIP (and services)
# 3) The Real Servers States
# 4) The VRRP states
#
# This plugin has been tested on Alteon 3408 but should work on other devices
# as far they support this two MIBS
# ALTEON-CHEETAH-LAYER4-MIB.mib
# ALTEON-CHEETAH-NETWORK-MIB.mib
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

############### BASE DIRECTORY FOR TEMP FILE (override this with -F) ########
my $o_base_dir="/tmp/tmp_Nagios_Alteon.";

# Alteon OIDs Indexes
my $alteon_real_server_index 				= '.1.3.6.1.4.1.1872.2.5.4.1.1.2.2.1.1';
my $alteon_virtual_server_index 			= '.1.3.6.1.4.1.1872.2.5.4.1.1.4.2.1.1';
my $alteon_service_by_vip_index 			= '.1.3.6.1.4.1.1872.2.5.4.1.1.4.5.1.1';
my $alteon_services_tcp_ports 				= '.1.3.6.1.4.1.1872.2.5.4.1.1.4.5.1.3';
# Alteon VIP OIDs
my $alteon_virtual_server_status			= '.1.3.6.1.4.1.1872.2.5.4.1.1.4.2.1.4';
my $alteon_virtual_server_desc 				= '.1.3.6.1.4.1.1872.2.5.4.1.1.4.2.1.10';
my $alteon_virtual_server_addr 				= '.1.3.6.1.4.1.1872.2.5.4.2.4.1.14';
my $alteon_virtual_server_tot_sess 			= '.1.3.6.1.4.1.1872.2.5.4.2.4.1.3';
my $alteon_virtual_server_high_sess 		= '.1.3.6.1.4.1.1872.2.5.4.2.4.1.5';
my $alteon_virtual_server_failures_sess 	= '.1.3.6.1.4.1.1872.2.5.4.2.4.1.4';
my $alteon_virtual_server_octets_sess 		= '.1.3.6.1.4.1.1872.2.5.4.2.4.1.8';
# Alteon RIP OIDs
my $alteon_real_server_status				= '.1.3.6.1.4.1.1872.2.5.4.1.1.2.2.1.10';
my $alteon_real_server_desc 				= '.1.3.6.1.4.1.1872.2.5.4.1.1.2.2.1.12';	# The name of the real server
my $alteon_real_server_addr 				= '.1.3.6.1.4.1.1872.2.5.4.1.1.2.2.1.2';	# IP address of the real server identified by the instance of the slbRealServerIndex.
my $alteon_real_server_state_by_vip 		= '.1.3.6.1.4.1.1872.2.5.4.3.4.1.6';
my $alteon_real_server_state 				= '.1.3.6.1.4.1.1872.2.5.4.3.1.1.7';
my $alteon_real_server_tot_sess 			= '.1.3.6.1.4.1.1872.2.5.4.2.2.1.3';
my $alteon_real_server_high_sess 			= '.1.3.6.1.4.1.1872.2.5.4.2.2.1.5';
my $alteon_real_server_failures_sess 		= '.1.3.6.1.4.1.1872.2.5.4.2.2.1.4';
my $alteon_real_server_octets_sess 			= '.1.3.6.1.4.1.1872.2.5.4.2.2.1.8';
# Alteon VRRP OIDs 
my $alteon_vrrp_addr 						= '.1.3.6.1.4.1.1872.2.5.3.1.6.3.1.3';
my $alteon_vrrp_state 						= '.1.3.6.1.4.1.1872.2.5.3.3.3.1.1.2';
# Alteon Ports states and stats
my $alteon_ports_states						= '.1.3.6.1.4.1.1872.2.5.1.1.2.2.1.2';
my $alteon_ports_in_errors					= '.1.3.6.1.4.1.1872.2.5.1.2.3.1.1.6';
my $alteon_ports_in_discards				= '.1.3.6.1.4.1.1872.2.5.1.2.3.1.1.5';
my $alteon_ports_in_traffic					= '.1.3.6.1.4.1.1872.2.5.1.2.3.1.1.2';
my $alteon_ports_out_errors					= '.1.3.6.1.4.1.1872.2.5.1.2.3.1.1.12';
my $alteon_ports_out_discards				= '.1.3.6.1.4.1.1872.2.5.1.2.3.1.1.11';
my $alteon_ports_out_traffic				= '.1.3.6.1.4.1.1872.2.5.1.2.3.1.1.8';

# Alteon SNMP States
my %real_server_state_by_vip = ( 1 => {	STATE => 'blocked', NAGIOS_STATE => 'WARNING' },
								 2 => {	STATE => 'running', NAGIOS_STATE => 'OK' },
								 3 => {	STATE => 'failed', NAGIOS_STATE => 'CRITICAL' },
								 4 => {	STATE => 'disabled', NAGIOS_STATE => 'OK' },
								 5 => {	STATE => 'slowstart', NAGIOS_STATE => 'WARNING' },
);
my %real_server_state = ( 2 => {	STATE => 'running', NAGIOS_STATE => 'OK' },
						  3 => {	STATE => 'failed', NAGIOS_STATE => 'CRITICAL' },
						  4 => {	STATE => 'disabled', NAGIOS_STATE => 'OK' },
);

my %vrrp_state = ( 1 => {	STATE => 'init', NAGIOS_STATE => 'OK' },
				   2 => {	STATE => 'master', NAGIOS_STATE => 'OK' },
				   3 => {	STATE => 'backup', NAGIOS_STATE => 'OK' },
				   4 => {	STATE => 'reset', NAGIOS_STATE => 'WARNING' },
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
# Misc Options
my $o_long_output = undef;
my %hash_sessions_stats_type = ( COUNTS => 1, FAILURES => 1, OCTETS => 1);

# Specific Alteon options
my $o_list = undef;
my $o_excl = undef;
my $o_check_by_vip = undef;
my $o_check_rip = undef;
my $o_check_vrrp = undef;
my $o_vip_sessions = undef;
my $o_rip_sessions = undef;
my $o_check_errors = undef;
my $o_check_traffic = undef;

# Misc variables
my $resultp = undef;
my @tmp = ();
my @tmp2 = ();
my %hash_ids = ();
my %hash_ids_excl = ();
my %hash_current = ();
my %hash_last = ();
my $vip_id = "";
my $output = "";
my $perfs = "";
my $exit_code = "OK";
my $id = "";
my $id_vip_tmp = "";
my $id_vip_svc_tmp = "";
my $id_rip_tmp = "";
my $sessions_test = undef;
my $oid_desc = undef;
my $oid_addr = undef;
my $oid_tot_sess = undef;
my $oid_high_sess = undef;
my $counts_hist = undef;
my $hcounts_hist = undef;
my $failures_hist = undef;
my $octets_hist = undef;
my $delta_time = undef;
my $count_sess = undef;
my $hcount_sess = undef;
my $oid_failures_sess = undef;
my $oid_octets_sess = undef;
my %hash_status = ();

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
    print "Usage: $0 [-v] -H <host> (-C <snmp_community> [-2]) | (-l login -x passwd [-X pass -L <authp>,<privp>)  [-p <port>] [-N <desc table oid>] -n <name in desc_oid> [-O <comments table OID>] [-i | -a | -D] [-r] [-f[eSyYZ] [-P <previous perf data from nagios \$SERVICEPERFDATA\$>] [-T <previous time from nagios \$LASTSERVICECHECK\$>] [--pcount=<hist size in perf>]] [-k[qBMGu] [-S [intspeed]] -g -w<warn levels> -c<crit levels> -d<delta>] [-o <octet_length>] [-m|-mm] [-t <timeout>] [-s] [--label] [--cisco=[oper,][addoper,][linkfault,][use_portnames|show_portnames]] [--stp[=<expected stp state>]] [-V]\n";
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

# keys become values and values become keys
sub reverse_hash {
	my $hash_in = shift;
	
	my %hash_out = ();
	foreach my $key (keys %$hash_in){
		$hash_out{$hash_in->{$key}} = $key;
	}
	return %hash_out;
}

sub ascii_to_hex { # Convert each ASCII character to a two-digit hex number [WL]
  (my $str = shift) =~ s/(.|\n)/sprintf("%02lx", ord $1)/eg;
  return $str;
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

sub help {
   print "\nSNMP Network Interface Monitor for Nagios (check_snmp_netint) v. ",$Version,"\n";
   print "GPL licence, (c)2004-2007 Patrick Proy, (c)2007-2008 William Leibzon\n";
   print "contribs by J. Jungmann, S. Probst, R. Leroy, M. Berger\n\n";
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
   
-w, --warning=
   
-c, --critical=
    
-F, --filestore[=<filename>]
  
   
-t, --timeout=INTEGER
   timeout for SNMP in seconds (Default: 5)   
   
-V, --version
   prints version number

EOT
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
	'D:s'   			=> \$o_dirstore,   	'dir-to-store:s' 	=> \$o_dirstore,
	'list:s' 			=> \$o_list,
	'exclude:s'			=> \$o_excl,
	'vip-sessions:s'	=> \$o_vip_sessions,
	'rip-sessions:s'	=> \$o_rip_sessions,
	'rs-state-by-vip'	=> \$o_check_by_vip,
	'rs-state'			=> \$o_check_rip,
	'vrrp-state:s'		=> \$o_check_vrrp,
	'traffic'			=> \$o_check_traffic,
	'errors'			=> \$o_check_errors,
	'long-output'		=> \$o_long_output,
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
if ( defined $o_vip_sessions ) {
	$o_vip_sessions = uc $o_vip_sessions;
	if ( not exists($hash_sessions_stats_type{$o_vip_sessions}) ){
		print "Don't understand what you try to retrieve : $o_vip_sessions, just know (COUNTS/FAILURES/OCTETS)\n";
		print_usage(); 
		exit $ERRORS{"UNKNOWN"};
	}
}
if ( defined $o_rip_sessions ) {
	$o_rip_sessions = uc $o_rip_sessions;
	if ( not exists($hash_sessions_stats_type{$o_rip_sessions}) ){
		print "Don't understand what you try to retrieve : $o_rip_sessions, just know (COUNTS/FAILURES/OCTETS)\n";
		print_usage(); 
		exit $ERRORS{"UNKNOWN"};
	}
}
$o_list = "ALL" unless $o_list;
if ( $o_check_vrrp ){
	$o_check_vrrp = lc($o_check_vrrp);
	if ( $o_check_vrrp ne "master" and $o_check_vrrp ne "backup" ){
		print "State for vrrp should be : master/backup\n";
		print_usage(); 
		exit $ERRORS{"UNKNOWN"};
	}
}
$o_dirstore = "/opt/nagios/var" unless $o_dirstore;
# Fix the names of history files

my $vip_failures_hist = $o_dirstore."/alteon_vip_failures_".$o_host;
my $vip_octets_hist = $o_dirstore."/alteon_vip_octets_".$o_host;
my $rip_counts_hist = $o_dirstore."/alteon_rip_counts_".$o_host;
my $rip_failures_hist = $o_dirstore."/alteon_rip_failures_".$o_host;
my $rip_octets_hist = $o_dirstore."/alteon_rip_octets_".$o_host;

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

if ( $o_vip_sessions or $o_rip_sessions){
	if ( $o_vip_sessions ){
		verb("Check VIPs sessions",1,$o_verb);
		verb("Get virtual servers status",1,$o_verb);
		%hash_status = get_table_by_id($session,$alteon_virtual_server_status,$o_verb);
		$sessions_test = $o_vip_sessions;
		$oid_desc = $alteon_virtual_server_desc;
		$oid_addr = $alteon_virtual_server_addr;
		$oid_tot_sess = $alteon_virtual_server_tot_sess;
		$oid_high_sess = $alteon_virtual_server_high_sess;
		$oid_failures_sess = $alteon_virtual_server_failures_sess;
		$oid_octets_sess = $alteon_virtual_server_octets_sess;
		$counts_hist = $o_dirstore."/alteon_vip_counts_".$o_host;
		$hcounts_hist = $o_dirstore."/alteon_vip_hcounts_".$o_host;
		$failures_hist = $o_dirstore."/alteon_vip_failures_".$o_host;
		$octets_hist = $o_dirstore."/alteon_vip_octets_".$o_host;
	}
	else {
		verb("Check RIPs sessions",1,$o_verb);
		verb("Get real servers states",1,$o_verb);
		%hash_status = get_table_by_id($session,$alteon_real_server_state,$o_verb);
		$sessions_test = $o_rip_sessions;
		$oid_desc = $alteon_real_server_desc;
		$oid_addr = $alteon_real_server_addr;
		$oid_tot_sess = $alteon_real_server_tot_sess;
		$oid_high_sess = $alteon_real_server_high_sess;
		$oid_failures_sess = $alteon_real_server_failures_sess;
		$oid_octets_sess = $alteon_real_server_octets_sess;
		$counts_hist = $o_dirstore."/alteon_rip_counts_".$o_host;
		$hcounts_hist = $o_dirstore."/alteon_rip_hcounts_".$o_host;
		$failures_hist = $o_dirstore."/alteon_rip_failures_".$o_host;
		$octets_hist = $o_dirstore."/alteon_rip_octets_".$o_host;
	}
	# Get virtual servers descriptions
	verb("Get servers descriptions",1,$o_verb);
	my %hash_desc = get_table_by_id($session,$oid_desc,$o_verb);	
	# Get virtual servers addresses
	verb("Get virtual servers addresses",1,$o_verb);
	my %hash_addr = get_table_by_id($session,$oid_addr,$o_verb);	
	# Ids to check
	my %hash_ids = get_id_list_to_check($o_list,$o_excl,\%hash_desc,\%hash_addr,$o_verb);
	if ( $sessions_test eq "COUNTS" ){
		verb("Get servers total sessions handled",1,$o_verb);
		my %hash_tot_sessions = get_table_by_id($session,$oid_tot_sess,$o_verb);
		# Now we have current data, we need old data
		if ( -s $counts_hist ){
			# We have history, it can work
			my %hash_tot_sessions_old = get_file($counts_hist);
			foreach my $id (keys %hash_ids) {
				$delta_time = time - $hash_tot_sessions_old{$id}{TIME};
				$count_sess = sprintf "%.2f",  ( ($hash_tot_sessions{$id} - $hash_tot_sessions_old{$id}{DATA}) / $delta_time );
				# Push informations only for active Servers
				if ( $hash_status{$id} == 2 ) {
					# Formating output
					$perfs .= " 'sess_".$hash_ids{$id}."'=".$count_sess.";;;;";
					if ( $o_crit_opt and ($count_sess >= $o_crit_opt) ) {
						$exit_code = "CRITICAL";
						$output .= "sessions (num/s):".$hash_ids{$id}.":".$count_sess."(".$exit_code.") ";
					}
					elsif ( $o_warn_opt and ($count_sess >= $o_warn_opt) and ($exit_code eq "OK") ) {
						$exit_code = "WARNING";
						$output .= "sessions (num/s):".$hash_ids{$id}.":".$count_sess."(".$exit_code.") ";
					}
					elsif ( $o_long_output ) {
						$output .= "sessions (num/s):".$hash_ids{$id}.":".$count_sess."(".$exit_code.") ";
					}
				}
			}
		}
		else {
			# no data, put the current data in history files and get stuff next time
			$exit_code = "OK";
			$output = "NO USABLE DATA, maybe next time";
		}
		# Finally push new values
		push_file($counts_hist, \%hash_tot_sessions);
	}
	if ( $sessions_test eq "HCOUNTS" ){
		verb("Get highest sessions handled",1,$o_verb);
		my %hash_high_sessions = get_table_by_id($session,$oid_high_sess,$o_verb);
		# Now we have current data, we need old data
		if ( -s $hcounts_hist ){
			# We have history, it can work
			my %hash_high_sessions_old = get_file($hcounts_hist);
			foreach my $id (keys %hash_ids) {
				$delta_time = time - $hash_high_sessions_old{$id}{TIME};
				$hcount_sess = sprintf "%.2f",  ( ($hash_high_sessions{$id} - $hash_high_sessions_old{$id}{DATA}) / $delta_time );
				# Push informations only for active Servers
				if ( $hash_status{$id} == 2 ) {
					# Formating output
					$perfs .= " 'hsess_".$hash_ids{$id}."'=".$hcount_sess.";;;;";
					if ( $o_crit_opt and ($count_sess >= $o_crit_opt) ) {
						$exit_code = "CRITICAL";
						$output .= "sessions (num/s):".$hash_ids{$id}.":".$hcount_sess."(".$exit_code.") ";
					}
					elsif ( $o_warn_opt and ($count_sess >= $o_warn_opt) and ($exit_code eq "OK") ) {
						$exit_code = "WARNING";
						$output .= "sessions (num/s):".$hash_ids{$id}.":".$hcount_sess."(".$exit_code.") ";
					}
					elsif ( $o_long_output ) {
						$output .= "sessions (num/s):".$hash_ids{$id}.":".$hcount_sess."(".$exit_code.") ";
					}
				}
			}
		}
		else {
			# no data, put the current data in history files and get stuff next time
			$exit_code = "OK";
			$output = "NO USABLE DATA, maybe next time";
		}
		# Finally push new values
		push_file($hcounts_hist, \%hash_high_sessions);
	}
	elsif ( $sessions_test eq "FAILURES" ){
		verb("Get servers failures",1,$o_verb);
		my %hash_failures_sessions = get_table_by_id($session,$oid_failures_sess,$o_verb);
		# Now we have current data, we need old data
		if ( -s $failures_hist ){
			# We have history, it can work
			my %hash_failures_sessions_old = get_file($failures_hist);
			foreach my $id (keys %hash_ids) {
				$delta_time = time - $hash_failures_sessions_old{$id}{TIME};
				$count_sess = sprintf "%.2f",  ( ($hash_failures_sessions{$id} - $hash_failures_sessions_old{$id}{DATA}) / $delta_time );
				# Formating output
				# Push informations only for active Servers
				if ( $hash_status{$id} == 2 ) {
					$perfs .= " 'failed_sessions_".$hash_ids{$id}."'=".$count_sess.";;;;";
					if ( $o_crit_opt and ($count_sess >= $o_crit_opt) ) {
						$exit_code = "CRITICAL";
						$output .= "Failed sessions (num/s):".$hash_ids{$id}.":".$count_sess."(".$exit_code.") ";
					}
					elsif ( $o_warn_opt and ($count_sess >= $o_warn_opt) and ($exit_code eq "OK") ) {
						$exit_code = "WARNING";
						$output .= "Failed sessions (num/s):".$hash_ids{$id}.":".$count_sess."(".$exit_code.") ";
					}
					elsif ( $o_long_output ) {
						$output .= "Failed sessions (num/s):".$hash_ids{$id}.":".$count_sess."(".$exit_code.") ";
					}
				}
			}
		}
		else {
			# no data, put the current data in history files and get stuff next time
			$exit_code = "OK";
			$output = "NO USABLE DATA, maybe next time";
		}
		# Finally push new values
		push_file($failures_hist, \%hash_failures_sessions);
	}
	elsif ( $sessions_test eq "OCTETS" ){
		verb("Get servers octets transmitted",1,$o_verb);
		my %hash_octets_sessions = get_table_by_id($session,$oid_octets_sess,$o_verb);
		# Now we have current data, we need old data
		if ( -s $octets_hist ){
			# We have history, it can work
			my %hash_octets_sessions_old = get_file($octets_hist);
			foreach my $id (keys %hash_ids) {
				$delta_time = time - $hash_octets_sessions_old{$id}{TIME};
				$count_sess = sprintf "%.2f",  ( ($hash_octets_sessions{$id} - $hash_octets_sessions_old{$id}{DATA}) / (1024 * 8 * $delta_time) );
				# Push informations only for active Servers
				if ( $hash_status{$id} == 2 ) {
					# Formating output
					$perfs .= " 'traffic_".$hash_ids{$id}."'=".$count_sess."kbps;;;;";
					if ( $o_crit_opt and ($count_sess >= $o_crit_opt) ) {
						$exit_code = "CRITICAL";
						$output .= "Traffic (kbps):".$hash_ids{$id}.":".$count_sess."(".$exit_code.") ";
					}
					elsif ( $o_warn_opt and ($count_sess >= $o_warn_opt) and ($exit_code eq "OK") ) {
						$exit_code = "WARNING";
						$output .= "Traffic (kbps):".$hash_ids{$id}.":".$count_sess."(".$exit_code.") ";
					}
					elsif ( $o_long_output ) {
						$output .= "Traffic (kbps):".$hash_ids{$id}.":".$count_sess."(".$exit_code.") ";
					}
				}
			}
		}
		else {
			# no data, put the current data in history files and get stuff next time
			$exit_code = "OK";
			$output = "NO USABLE DATA, maybe next time";
		}
		# Finally push new values
		push_file($octets_hist, \%hash_octets_sessions);
	}
	if ( ($exit_code eq "OK") and not $o_long_output ){ 
		$output = "Sessions OK " if not $output;
	}	
}
elsif ( $o_check_by_vip ){
	my %hash_vip_infos = ();
	my %hash_vip_ids = ();
	my %hash_exclude = ();
	# Get virtual servers status
	verb("Get virtual servers status",1,$o_verb);
	my %hash_vip_status = get_table_by_id($session,$alteon_virtual_server_status,$o_verb);	
	#Get real servers status
	# verb("Get real servers status",1,$o_verb);
	# my %hash_rip_status = get_table_by_id($session,$alteon_real_server_status,$o_verb);	
	# Get virtual servers descriptions
	verb("Get virtual servers descriptions",1,$o_verb);
	my %hash_vip_desc = get_table_by_id($session,$alteon_virtual_server_desc,$o_verb);	
	#$hash_vip_desc{1} = "toto";
	#$hash_vip_desc{51} = "titi";
	# Get virtual servers addresses
	verb("Get virtual servers addresses",1,$o_verb);
	my %hash_vip_addr = get_table_by_id($session,$alteon_virtual_server_addr,$o_verb);	
	# Now we can create the id list of VIP to check
	my %hash_ids = get_id_list_to_check($o_list,$o_excl,\%hash_vip_desc,\%hash_vip_addr,$o_verb);
	#print Dumper(%hash_ids);
	# Get Real servers Informations
	verb("Get real servers descriptions",1,$o_verb);
	my %hash_rip_infos_by_desc = get_table_by_id($session,$alteon_real_server_desc,$o_verb);
	verb("Get real servers addresses",1,$o_verb);
	my %hash_rip_infos_by_addr = get_table_by_id($session,$alteon_real_server_addr,$o_verb);
	# Get services ports
	verb("Get services tcp ports",1,$o_verb);
	my %hash_services_tcp_ports = get_table_by_id($session,$alteon_services_tcp_ports,$o_verb);
	# And finally, State of real servers
	verb("Get real servers states",1,$o_verb);
	my %hash_real_servers_states = get_table_by_id($session,$alteon_real_server_state_by_vip,$o_verb);
	verb("===> All informations retrieved",1,$o_verb);
	$exit_code = "OK";
	foreach my $id ( keys %hash_real_servers_states ) {
		# split id into his components
		$id =~ /(\d+)\.(\d+)\.(\d+)/;
		$id_vip_tmp = $1;
		$id_vip_svc_tmp = $1.".".$2;
		$id_rip_tmp = $3;
		verb("\$id=$id, \$id_vip_tmp=$id_vip_tmp(".$hash_ids{$id_vip_tmp}.")(".$hash_vip_status{$id_vip_tmp}."), \$id_vip_svc_tmp=$id_vip_svc_tmp(".$hash_services_tcp_ports{$id_vip_svc_tmp}."), \$id_rip_tmp=$id_rip_tmp(".$hash_rip_infos_by_desc{$id_rip_tmp}.")",2,$o_verb);
		if ( exists($hash_ids{$id_vip_tmp}) and ($hash_vip_status{$id_vip_tmp} == 2) ){
			#verb("VIP $id_vip_tmp is active, check state",2,$o_verb);
			if ( $real_server_state_by_vip{$hash_real_servers_states{$id}}{NAGIOS_STATE} ne "OK" or $o_long_output ) {
				if ( exists($hash_rip_infos_by_desc{$id_rip_tmp}) and $hash_rip_infos_by_desc{$id_rip_tmp} ){
					$output .= $hash_ids{$id_vip_tmp}."/".$hash_rip_infos_by_desc{$id_rip_tmp}."/tcp".$hash_services_tcp_ports{$id_vip_svc_tmp}.":".$real_server_state_by_vip{$hash_real_servers_states{$id}}{STATE}." ";
				}
				else {
					$output .= $hash_ids{$id_vip_tmp}."/".$hash_rip_infos_by_addr{$id_rip_tmp}."/tcp".$hash_services_tcp_ports{$id_vip_svc_tmp}.":".$real_server_state_by_vip{$hash_real_servers_states{$id}}{STATE}." ";
				}	
				if ( $exit_code ne "CRITICAL" ){
					$exit_code = $real_server_state_by_vip{$hash_real_servers_states{$id}}{NAGIOS_STATE};
				}
			}
		}
		else {
			verb("VIP $id_vip_tmp is inactive, pass...",2,$o_verb);
		}
	}
	if ( not $o_long_output and ($exit_code eq "OK") ){
		$output = "All Real Servers are OK";
	}
}
elsif ( $o_check_rip ){
	# Get Real servers Informations
	verb("Get real servers descriptions",1,$o_verb);
	my %hash_rip_infos_by_desc = get_table_by_id($session,$alteon_real_server_desc,$o_verb);
	verb("Get real servers addresses",1,$o_verb);
	my %hash_rip_infos_by_addr = get_table_by_id($session,$alteon_real_server_addr,$o_verb);
	# And finally, State of real servers
	verb("Get real servers states",1,$o_verb);
	my %hash_real_servers_states = get_table_by_id($session,$alteon_real_server_state,$o_verb);
	verb("===> All informations retrieved",1,$o_verb);
	my %hash_ids = get_id_list_to_check($o_list,$o_excl,\%hash_rip_infos_by_desc,\%hash_rip_infos_by_addr,$o_verb);
	$exit_code = "OK";
	foreach my $id ( keys %hash_ids ) {
		verb("\$id=$id",2,$o_verb);
		if ( ($real_server_state{$hash_real_servers_states{$id}}{NAGIOS_STATE}) ne "OK" or $o_long_output ) {
			if ( exists($hash_rip_infos_by_desc{$id}) and $hash_rip_infos_by_desc{$id} ){
				$output .= $hash_rip_infos_by_desc{$id}.":".$real_server_state{$hash_real_servers_states{$id}}{STATE}." ";
			}
			else {
				$output .= $hash_rip_infos_by_addr{$id}.":".$real_server_state{$hash_real_servers_states{$id}}{STATE}." ";
			}
			if ( $exit_code ne "CRITICAL" ){
				$exit_code = $real_server_state{$hash_real_servers_states{$id}}{NAGIOS_STATE};
			}
		}
	}	
	if ( not $o_long_output and ($exit_code eq "OK") ){
		$output = "All Real Servers are OK";
	}
}
elsif ( $o_check_vrrp ) {
	# Get VRRP Informations
	verb("Get vrrp addresses",1,$o_verb);
	my %hash_vrrp_addr = get_table_by_id($session,$alteon_vrrp_addr,$o_verb);
	verb("Get vrrp states",1,$o_verb);
	my %hash_vrrp_states = get_table_by_id($session,$alteon_vrrp_state,$o_verb);
	verb("===> All informations retrieved",1,$o_verb);
	my %hash_ids = get_id_list_to_check($o_list,$o_excl,\%hash_vrrp_addr,\%hash_vrrp_addr,$o_verb);
	$exit_code = "OK";
	foreach my $id ( keys %hash_ids ) {
		verb("\$id=$id $hash_vrrp_states{$id} $vrrp_state{$hash_vrrp_states{$id}}{STATE}",2,$o_verb);
		if ( $vrrp_state{$hash_vrrp_states{$id}}{STATE} eq "holdoff" ){
			$exit_code = "CRITICAL";
			$output .= $hash_vrrp_addr{$id}.":".$vrrp_state{$hash_vrrp_states{$id}}{STATE}." ";
		}
		elsif ( $vrrp_state{$hash_vrrp_states{$id}}{STATE} eq "init" and $o_long_output ){
			$output .= $hash_vrrp_addr{$id}.":".$vrrp_state{$hash_vrrp_states{$id}}{STATE}." ";
		}
		elsif ( ($vrrp_state{$hash_vrrp_states{$id}}{STATE}) ne $o_check_vrrp ) {
			if ( $exit_code eq "OK" ) { $exit_code = "WARNING"; }
			$output .= $hash_vrrp_addr{$id}.":".$vrrp_state{$hash_vrrp_states{$id}}{STATE}." ";
		}
		elsif ($o_long_output ) {
			$output .= $hash_vrrp_addr{$id}.":".$vrrp_state{$hash_vrrp_states{$id}}{STATE}." ";
		}
	}
	if ( not $o_long_output and ($exit_code eq "OK") ){
		$output = "All VRRPs are in $o_check_vrrp state";
	}
}
elsif ( $o_check_traffic ){
	my $count_in = undef;
	my $count_out = undef;
	my $traffic_in_hist = $o_dirstore."/alteon_traffic_in_".$o_host;
	my $traffic_out_hist = $o_dirstore."/alteon_traffic_out_".$o_host;
	# Get Ports states
	verb("Get Ports States",1,$o_verb);
	my %hash_ports_states = get_table_by_id($session,$alteon_ports_states,$o_verb);
	verb("Get Traffic IN",1,$o_verb);
	my %hash_ports_traffic_in = get_table_by_id($session,$alteon_ports_in_traffic,$o_verb);
	verb("Get Traffic OUT",1,$o_verb);
	my %hash_ports_traffic_out = get_table_by_id($session,$alteon_ports_out_traffic,$o_verb);
	my @port_list = get_port_list_to_check($o_list,$o_excl,\%hash_ports_states,$o_verb);
	verb("===> All informations retrieved",1,$o_verb);
	if ( -s $traffic_in_hist and -s $traffic_out_hist ){
		# We have history, it can work
		my %hash_traffic_in_old = get_file($traffic_in_hist);
		my %hash_traffic_out_old = get_file($traffic_out_hist);
		foreach my $port (sort @port_list) {
			# Check only active interfaces
			if ( $hash_ports_states{$port} == 2 ){
				$delta_time = time - $hash_traffic_in_old{$port}{TIME};
				$count_in = sprintf "%.2f",  ( ($hash_ports_traffic_in{$port} - $hash_traffic_in_old{$port}{DATA}) / (1024 * 8 * $delta_time) );
				$count_out = sprintf "%.2f",  ( ($hash_ports_traffic_out{$port} - $hash_traffic_out_old{$port}{DATA}) / (1024 * 8 * $delta_time) );
				# Formating output
				$perfs .= " 'traffic_in_port_".$port."'=".$count_in."kbps;;;; 'traffic_out_port_".$port."'=".$count_out."kbps;;;;";
				if ( $o_crit_opt and ( ($count_in >= $o_crit_opt) or ($count_out >= $o_crit_opt)) ) {
					$exit_code = "CRITICAL";
					$output .= "traffic port ".$port." (".$count_in."kbps/".$count_out."kbps); ";
				}
				elsif ( $o_warn_opt and (($count_in >= $o_warn_opt) or ($count_out >= $o_warn_opt)) and ($exit_code eq "OK") ) {
					$exit_code = "WARNING";
					$output .= "traffic port ".$port." (".$count_in."kbps/".$count_out."kbps); ";
				}
				elsif ( $o_long_output ) {
					$output .= "traffic port ".$port." (".$count_in."kbps/".$count_out."kbps); ";
				}
			}
		}
	}
	else {
		# no data, put the current data in history files and get stuff next time
		$exit_code = "OK";
		$output = "NO USABLE DATA, maybe next time";
	}
	# Finally push new values
	push_file($traffic_in_hist, \%hash_ports_traffic_in);
	push_file($traffic_out_hist, \%hash_ports_traffic_out);
	if ( not $o_long_output and ($exit_code eq "OK") ){
		$output = "Traffic OK";
	}
}
elsif ( $o_check_errors ){
	my $errors_in = undef;
	my $errors_out = undef;
	my $discards_in = undef;
	my $discards_out = undef;
	my $errors_in_hist = $o_dirstore."/alteon_errors_in_".$o_host;
	my $errors_out_hist = $o_dirstore."/alteon_errors_out_".$o_host;
	my $discards_in_hist = $o_dirstore."/alteon_discards_in_".$o_host;
	my $discards_out_hist = $o_dirstore."/alteon_discards_out_".$o_host;
	# Get Ports states
	verb("Get Ports States",1,$o_verb);
	my %hash_ports_states = get_table_by_id($session,$alteon_ports_states,$o_verb);
	verb("Get Errors IN",1,$o_verb);
	my %hash_ports_errors_in = get_table_by_id($session,$alteon_ports_in_errors,$o_verb);
	verb("Get Errors OUT",1,$o_verb);
	my %hash_ports_errors_out = get_table_by_id($session,$alteon_ports_out_errors,$o_verb);
	verb("Get Discards IN",1,$o_verb);
	my %hash_ports_discards_in = get_table_by_id($session,$alteon_ports_in_discards,$o_verb);
	verb("Get Discards OUT",1,$o_verb);
	my %hash_ports_discards_out = get_table_by_id($session,$alteon_ports_out_discards,$o_verb);
	my @port_list = get_port_list_to_check($o_list,$o_excl,\%hash_ports_states,$o_verb);
	verb("===> All informations retrieved",1,$o_verb);
	if ( -s $errors_in_hist and -s $errors_out_hist and -s $discards_in_hist and -s $discards_out_hist){
		# We have history, it can work
		my %hash_errors_in_old = get_file($errors_in_hist);
		my %hash_errors_out_old = get_file($errors_out_hist);
		my %hash_discards_in_old = get_file($discards_in_hist);
		my %hash_discards_out_old = get_file($discards_out_hist);
		foreach my $port (sort @port_list) {
			# Check only active interfaces
			if ( $hash_ports_states{$port} == 2 ){
				$delta_time = time - $hash_errors_in_old{$port}{TIME};
				$errors_in = sprintf "%.2f",  ( ($hash_ports_errors_in{$port} - $hash_errors_in_old{$port}{DATA}) / $delta_time );
				$errors_out = sprintf "%.2f",  ( ($hash_ports_errors_out{$port} - $hash_errors_out_old{$port}{DATA}) / $delta_time );
				$discards_in = sprintf "%.2f",  ( ($hash_ports_discards_in{$port} - $hash_discards_in_old{$port}{DATA}) / $delta_time );
				$discards_out = sprintf "%.2f",  ( ($hash_ports_discards_out{$port} - $hash_discards_out_old{$port}{DATA}) / $delta_time );
				# Formating output
				$perfs .= " 'errors_in_port_".$port."'=".$errors_in."/s;;;; 'errors_out_port_".$port."'=".$errors_out."/s;;;;";
				$perfs .= " 'discards_in_port_".$port."'=".$discards_in."/s;;;; 'discards_out_port_".$port."'=".$discards_out."/s;;;;";
				if ( $o_crit_opt and ( ($errors_in >= $o_crit_opt) or ($errors_out >= $o_crit_opt) or ($discards_in >= $o_crit_opt) or ($discards_out >= $o_crit_opt)) ) {
					$exit_code = "CRITICAL";
					$output .= "Port ".$port.": Errors(".$errors_in."ps/".$errors_out."ps) Discards(".$discards_in."ps/".$discards_out."ps); ";
				}
				elsif ( $o_warn_opt and (($errors_in >= $o_warn_opt) or ($errors_out >= $o_warn_opt) or ($discards_in >= $o_warn_opt) or ($discards_out >= $o_warn_opt)) and ($exit_code eq "OK") ) {
					$exit_code = "WARNING";
					$output .= "Port ".$port.": Errors(".$errors_in."ps/".$errors_out."ps) Discards(".$discards_in."ps/".$discards_out."ps); ";
				}
				elsif ( $o_long_output ) {
					$output .= "Port ".$port.": Errors(".$errors_in."ps/".$errors_out."ps) Discards(".$discards_in."ps/".$discards_out."ps); ";
				}
			}
		}
	}
	else {
		# no data, put the current data in history files and get stuff next time
		$exit_code = "OK";
		$output = "NO USABLE DATA, maybe next time";
	}
	# Finally push new values
	push_file($errors_in_hist, \%hash_ports_errors_in);
	push_file($errors_out_hist, \%hash_ports_errors_out);
	push_file($discards_in_hist, \%hash_ports_discards_in);
	push_file($discards_out_hist, \%hash_ports_discards_out);
	if ( not $o_long_output and ($exit_code eq "OK") ){
		$output = "Errors/Discards OK";
	}
}
else {
	# you shouldn't be here.... in the twilight zone
}

print "$exit_code - $output | $perfs\n";
exit $ERRORS{$exit_code};


