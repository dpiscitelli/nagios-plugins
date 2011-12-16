#!/usr/bin/perl -w
#
# ============================== SUMMARY =====================================
#
# Program : check_juniper_isg1000.pl
# Version : 1.0
# Date    : 2011/12/12
# Authors : piscitelli.david@gmail.com
#           
# Licence : GPL - summary below, full text at http://www.fsf.org/licenses/gpl.txt
#
# =========================== PROGRAM LICENSE =================================
# check_juniper_isg1000.pl, monitor Cisco Catalyst devices
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
my $netscreenNsrpGeneral 	= '.1.3.6.1.4.1.3224.6.1';
my $nsrpVsdMemberTable		= '.1.3.6.1.4.1.3224.6.2.2';
my $nsIfName				= '.1.3.6.1.4.1.3224.9.1.1.2';
my $nsIfStatus				= '.1.3.6.1.4.1.3224.9.1.1.5';
my $nsIfFlowInByte			= '.1.3.6.1.4.1.3224.9.3.1.3';
my $nsIfFlowOutByte			= '.1.3.6.1.4.1.3224.9.3.1.5';
my $nsIfMonTrMngDrop		= '.1.3.6.1.4.1.3224.9.4.1.7';

my %hash_nsrpVsdMemberStatus_status = ( 0 => {	STATE => 'undefined', NAGIOS_STATE => 'CRITICAL' },
										1 => {	STATE => 'init', NAGIOS_STATE => 'CRITICAL' },
										2 => {	STATE => 'master', NAGIOS_STATE => 'OK' },
										3 => {	STATE => 'primary-backup', NAGIOS_STATE => 'OK' },
										4 => {	STATE => 'backup', NAGIOS_STATE => 'WARNING' },
										5 => {	STATE => 'ineligible', NAGIOS_STATE => 'CRITICAL' },
										6 => {	STATE => 'inoperable', NAGIOS_STATE => 'CRITICAL' },
);

my %hash_nsIfStatuss_states = ( 0 => {	STATE => 'down', NAGIOS_STATE => 'CRITICAL' },
								1 => {	STATE => 'up', NAGIOS_STATE => 'OK' },
								2 => {	STATE => 'ready', NAGIOS_STATE => 'WARNING' },
								3 => {	STATE => 'inactive', NAGIOS_STATE => 'CRITICAL' }
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
my $o_check_cluster = 0;
my $o_state = undef;
my $o_check_status = undef;
my $o_check_traffic = undef;
my $o_check_packets = undef;
my $o_interfaces = undef;

# Misc variables
my $output = "";
my $perfs = "";
my $exit_code = "OK";
my %hash_parse_config = ();


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
	'check-cluster'		=> \$o_check_cluster,
	'state:s'			=> \$o_state,
	'traffic'			=> \$o_check_traffic,
	'status'			=> \$o_check_status,
	'packet-drop'		=> \$o_check_packets,
	'n:s'				=> \$o_interfaces,
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
if ( $o_check_cluster and not $o_state ){
	print "option --state is not defined : master/primary-backup\n";
	exit $ERRORS{UNKNOWN};
}
if ( $o_state ){
	$o_state = lc $o_state;
	if ( ($o_state ne "master") and ($o_state ne "primary-backup") ) {
		print "option --state should be : master/primary-backup\n";
		exit $ERRORS{UNKNOWN};
	}
}
$o_interfaces = "FOO_ALL_FOO" unless $o_interfaces;

$o_dirstore = "/opt/nagios/var" unless $o_dirstore;
if ( not -d $o_dirstore."/".$o_host ){
	mkdir $o_dirstore."/".$o_host
		or die "Impossible to create ".$o_dirstore."/".$o_host." directory";
	$o_dirstore = $o_dirstore."/".$o_host;
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

if ( $o_check_cluster ){
	# Firt get the local id of this cluster node
	verb("Get Node Cluster Id",1,$o_verb);
	my %hash_cluster_node = get_table_by_id($session,$netscreenNsrpGeneral,$o_verb);	
	my $local_id = $hash_cluster_node{'2.0'};
	verb("Local Id : $local_id",1,$o_verb);
	# Get Cluster Members status
	verb("Get Clusters Members status",1,$o_verb);
	my %hash_cluster_members = get_table_by_id($session,$nsrpVsdMemberTable,$o_verb);	
	my $id_klum = undef;
	foreach my $id (keys %hash_cluster_members ){
		if ( $hash_cluster_members{$id} == $local_id ){
			# Get the SNMP id of the node
			$id_klum = $id;
		}
	}
	# Now get the status of the node and compare it to the attempted status
	$id_klum =~ m/\d+\.\d+\.(\d+)/;
	my $node_status = $hash_cluster_members{'1.3.'.$1};
	verb("Node status : $node_status",2,$o_verb);
	if ( $hash_nsrpVsdMemberStatus_status{$node_status}{STATE} ne $o_state ){
		$output = "Member Status is ".$hash_nsrpVsdMemberStatus_status{$node_status}{STATE}.", should be ".$o_state." ";
		$exit_code = "CRITICAL";
	}
	else {
		$output = "Member Status is OK : ".$hash_nsrpVsdMemberStatus_status{$node_status}{STATE}." ";
	}
}
elsif ( $o_check_status ){
	# Get Interfaces by name
	verb("Get Interfaces by name",1,$o_verb);
	my %hash_interface_names = get_table_by_id($session,$nsIfName,$o_verb);	
	# Get Interface status
	verb("Get Interface status",1,$o_verb);
	my %hash_interface_status = get_table_by_id($session,$nsIfStatus,$o_verb);	
	foreach my $id ( keys %hash_interface_names ){
		# Check only physical interfaces... named etherneti/j
		if ( $hash_interface_names{$id} =~ m/^ethernet\d+\/\d+$/ ){
			if ( $o_interfaces eq "FOO_ALL_FOO" or $hash_interface_names{$id} =~ m/$o_interfaces/ ){
				verb("Check Interface: ".$hash_interface_names{$id},2,$o_verb);
				if ( $hash_nsIfStatuss_states{$hash_interface_status{$id}}{NAGIOS_STATE} eq "CRITICAL" ){
					$exit_code = "CRITICAL";
					$output .= "Int(".$hash_interface_names{$id}.":".$hash_nsIfStatuss_states{$hash_interface_status{$id}}{STATE}.") ";
				}
				elsif ( $hash_nsIfStatuss_states{$hash_interface_status{$id}}{NAGIOS_STATE} eq "WARNING" ){
					$exit_code = "WARNING" if $exit_code eq "OK";
					$output .= " Int(".$hash_interface_names{$id}.":".$hash_nsIfStatuss_states{$hash_interface_status{$id}}{STATE}.") ";
				}
			}
		}
	}
	if ( $exit_code eq "OK" ){
		$output = "All Interfaces are UP";
	}
}
elsif ( $o_check_traffic ){
	my $delta_time = undef;
	my $count_in = undef;
	my $count_out = undef;
	my $history_traffic_in = $o_dirstore."/isg1000_in_".$o_host;
	my $history_traffic_out = $o_dirstore."/isg1000_out_".$o_host;
	# Get Interfaces by name
	verb("Get Interfaces by name",1,$o_verb);
	my %hash_interface_names = get_table_by_id($session,$nsIfName,$o_verb);	
	verb("Get Traffic IN",1,$o_verb);
	my %hash_traffic_in = get_table_by_id($session,$nsIfFlowInByte,$o_verb);
	verb("Get Traffic OUT",1,$o_verb);
	my %hash_traffic_out = get_table_by_id($session,$nsIfFlowOutByte,$o_verb);
	# Get Interface status
	verb("Get Interface status",1,$o_verb);
	my %hash_interface_status = get_table_by_id($session,$nsIfStatus,$o_verb);	
	if ( -s $history_traffic_in and -s $history_traffic_out ){
		# We have history, it can work
		my %hash_traffic_in_old = get_file($history_traffic_in);
		my %hash_traffic_out_old = get_file($history_traffic_out);
		foreach my $id ( keys %hash_interface_names ){
			# Check only physical interfaces... named etherneti/j.... and UP
			if ( ($hash_interface_names{$id} =~ m/^ethernet\d+\/\d+$/) and ($hash_interface_status{$id} == 1) ){
				if ( $o_interfaces eq "FOO_ALL_FOO" or $hash_interface_names{$id} =~ m/$o_interfaces/ ){
					verb("Check Interface: ".$hash_interface_names{$id},2,$o_verb);
					$delta_time = time - $hash_traffic_in_old{$id}{TIME};
					$count_in = sprintf "%.2f",  ( ($hash_traffic_in{$id} - $hash_traffic_in_old{$id}{DATA}) / (1024 * 8 * $delta_time) );
					$count_out = sprintf "%.2f",  ( ($hash_traffic_out{$id} - $hash_traffic_out_old{$id}{DATA}) / (1024 * 8 * $delta_time) );
					# Formating output
					$perfs .= " 'traffic_in_".$hash_interface_names{$id}."'=".$count_in."kbps;;;; 'traffic_out_".$hash_interface_names{$id}."'=".$count_out."kbps;;;;";
					if ( $o_crit_opt and ( ($count_in >= $o_crit_opt) or ($count_out >= $o_crit_opt)) ) {
						$exit_code = "CRITICAL";
						$output .= "traffic port ".$hash_interface_names{$id}." (".$count_in."kbps/".$count_out."kbps); ";
					}
					elsif ( $o_warn_opt and (($count_in >= $o_warn_opt) or ($count_out >= $o_warn_opt)) and ($exit_code eq "OK") ) {
						$exit_code = "WARNING";
						$output .= "traffic port ".$hash_interface_names{$id}." (".$count_in."kbps/".$count_out."kbps); ";
					}
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
elsif ( $o_check_packets ){
	my $delta_time = undef;
	my $count = undef;
	my $history_packet_drop = $o_dirstore."/isg1000_packets_".$o_host;
	# Get Interfaces by name
	verb("Get Interfaces by name",1,$o_verb);
	my %hash_interface_names = get_table_by_id($session,$nsIfName,$o_verb);	
	verb("Get Drop packets",1,$o_verb);
	my %hash_packet_drop = get_table_by_id($session,$nsIfMonTrMngDrop,$o_verb);
	# Get Interface status
	verb("Get Interface status",1,$o_verb);
	my %hash_interface_status = get_table_by_id($session,$nsIfStatus,$o_verb);	
	if ( -s $history_packet_drop ){
		# We have history, it can work
		my %hash_packet_drop_old = get_file($history_packet_drop);
		foreach my $id ( keys %hash_interface_names ){
			# Check only physical interfaces... named etherneti/j.... and UP
			if ( ($hash_interface_names{$id} =~ m/^ethernet\d+\/\d+$/) and ($hash_interface_status{$id} == 1) ){
				if ( $o_interfaces eq "FOO_ALL_FOO" or $hash_interface_names{$id} =~ m/$o_interfaces/ ){
					verb("Check Interface: ".$hash_interface_names{$id},2,$o_verb);
					$delta_time = time - $hash_packet_drop_old{$id}{TIME};
					$count = sprintf "%.2f",  ( ($hash_packet_drop{$id} - $hash_packet_drop_old{$id}{DATA}) / (1024 * 8 * $delta_time) );
					# Formating output
					$perfs .= " 'drop_".$hash_interface_names{$id}."'=".$count."ps;;;;";
					if ( $o_crit_opt and  ($count >= $o_crit_opt) ) {
						$exit_code = "CRITICAL";
						$output .= "Packet drop ".$hash_interface_names{$id}." (".$count."ps); ";
					}
					elsif ( $o_warn_opt and ($count >= $o_warn_opt) and ($exit_code eq "OK") ) {
						$exit_code = "WARNING";
						$output .= "Packet drop ".$hash_interface_names{$id}." (".$count."ps); ";
					}
				}
			}
		}
		if ( $exit_code eq "OK" ){
			$output = "Packet drop OK";
		}
	}
	else {
		# no data, put the current data in history files and get stuff next time
		$exit_code = "OK";
		$output = "NO USABLE DATA, maybe next time";
	}
	# Finally push new values
	push_file($history_packet_drop, \%hash_packet_drop);
}

print "$exit_code - $output | $perfs\n";
exit $ERRORS{$exit_code};


