#!/usr/bin/perl -w
#
# ============================== SUMMARY =====================================
#
# Program : check_gsa.pl
# Version : 1.0
# Date    : 01/27/2012
# Authors : piscitelli.david@gmail.com
#           
# Licence : GPL - summary below, full text at http://www.fsf.org/licenses/gpl.txt
#
# =========================== PROGRAM LICENSE =================================
# check_gsa.pl, monitor Google Search Appliance by SNMP
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
# Dependances: Net-SNMP with Net::SNMP perl library installed
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

# GSA OIDs
my $crawlRunning 		= '.1.3.6.1.4.1.11129.1.1.1.0';
my $diskHealth 			= '.1.3.6.1.4.1.11129.1.3.1.1.0';
my $diskErrors 			= '.1.3.6.1.4.1.11129.1.3.1.2.0';
my $temperatureHealth	= '.1.3.6.1.4.1.11129.1.3.2.1.0';
my $temperatureErrors	= '.1.3.6.1.4.1.11129.1.3.2.2.0';
my $machineHealth		= '.1.3.6.1.4.1.11129.1.3.3.1.0';
my $machineErrors		= '.1.3.6.1.4.1.11129.1.3.3.2.0';
my $docsServed			= '.1.3.6.1.4.1.11129.1.1.2.1.0';
my $crawlingRate		= '.1.3.6.1.4.1.11129.1.1.2.2.0';
my $todayDocsCrawled	= '.1.3.6.1.4.1.11129.1.1.2.4.0';
my $docErrors			= '.1.3.6.1.4.1.11129.1.1.2.5.0';
my $docsFound			= '.1.3.6.1.4.1.11129.1.1.2.6.0';
my $qpm 				= '.1.3.6.1.4.1.11129.1.2.1.0';

# Monitoring GSA Health States
my %health_states = ( 0 => { STATE => 'green', NAGIOS_STATE => 'OK' },
					  1 => { STATE => 'yellow', NAGIOS_STATE => 'WARNING' },
					  2 => { STATE => 'red', NAGIOS_STATE => 'CRITICAL' },
);


# Standard options
my $o_host = 		undef; 	# hostname
my $o_timeout =  	undef;  # Timeout (Default 10) 
my $o_help =		undef; 	# wan't some help ?
my $o_verb =		0;		# verbose mode
my $o_version =		undef;	# print version
my $o_warn_opt =   	"";  # warning options
my $o_crit_opt = 	"";  # critical options
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
# GSA options
my $o_check_crawl = 0;
my $o_check_disk_health = 0;
my $o_check_temperature_health = 0;
my $o_check_machine_health = 0;
my $o_check_docs_served = 0;
my $o_check_crawling_rate = 0;
my $o_check_today_docs_crawled = 0;
my $o_check_doc_errors = 0;
my $o_check_docs_found = 0;
my $o_check_qpm = 0;

# Misc variables
my $exit_code = "OK";
my $output = "";
my $perfs = "";
my $result = undef;
my $result2 = undef;

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

sub p_version { print "check_gsa version : $Version\n"; }

sub print_usage {
    print "Usage: $0 [-v] -H <host> (-C <snmp_community> [-2]) | (-l login -x passwd [-X pass -L <authp>,<privp>) [-p <port>] ";
	print "-w<warn levels> -c<crit levels> [-o <octet_length>] [-t <timeout>] [-V] ";
	print "--check-crawl | --check-disk | --check-temperature | --check-machine | --docs-served | --crawling-rate | --today-docs-crawled | --doc-errors | --docs-found | --qpm\n";
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

sub ascii_to_hex { # Convert each ASCII character to a two-digit hex number [WL]
  (my $str = shift) =~ s/(.|\n)/sprintf("%02lx", ord $1)/eg;
  return $str;
}

sub help {
   print "\nMonitor Google Search Appliance (check_gsa.pl) v. ",$Version,"\n";
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
   Warning threshold
   
-c, --critical=
   Critical threshold
   
-t, --timeout=INTEGER
   timeout for SNMP in seconds (Default: 5)   
   
-V, --version
   prints version number

--check-crawl
   Check Crawling activity (always OK, just information)
   
--check-disk
   Check disk(s) status
   
--check-temperature		
   Check Temperature of GSA
	
--check-machine
   Check the machine health
   
--docs-served
   Check the number of documents being served by GSA			
	
--crawling-rate
   Check the current crawling rate
   
--today-docs-crawled
   Check the number of documents crawled today
   
--doc-errors	
   Check the number of times an error occurred while trying to crawl a document
	
--docs-found
   Check the Total documents found by the GSA			

--qpm
   Check the queries per minute being handled
   
EOT
}

##########################################################################
#                                                                        #    
#	MAIN PROGRAM                                                         #
#                                                                        #
#                                                                        #
##########################################################################

Getopt::Long::Configure ("bundling");
GetOptions(
 	'v:i'					=> \$o_verb,		'verbose:i'			=> \$o_verb,
    'h'     				=> \$o_help,    	'help'        		=> \$o_help,
    'H:s'   				=> \$o_host,		'hostname:s'		=> \$o_host,
    'p:i'   				=> \$o_port,   		'port:i'			=> \$o_port,
    'C:s'   				=> \$o_community,	'community:s'		=> \$o_community,
	'2'						=> \$o_version2,	'v2c'				=> \$o_version2,
	'l:s'					=> \$o_login,		'login:s'			=> \$o_login,
	'x:s'					=> \$o_passwd,		'passwd:s'			=> \$o_passwd,
	'X:s'					=> \$o_privpass,	'privpass:s'		=> \$o_privpass,
	'L:s'					=> \$v3protocols,	'protocols:s'		=> \$v3protocols,
    't:i'   				=> \$o_timeout,    	'timeout:i'			=> \$o_timeout,
	'V'						=> \$o_version,		'version'			=> \$o_version,
    'w:s'   				=> \$o_warn_opt,    'warning:s'   		=> \$o_warn_opt,
    'c:s'   				=> \$o_crit_opt,    'critical:s'   		=> \$o_crit_opt,
    'o:i'   				=> \$o_octetlength, 'octetlength:i' 	=> \$o_octetlength,
	'check-crawl'			=> \$o_check_crawl,
	'check-disk'			=> \$o_check_disk_health,
	'check-temperature'		=> \$o_check_temperature_health,
	'check-machine'			=> \$o_check_machine_health,
	'docs-served'			=> \$o_check_docs_served,
	'crawling-rate'			=> \$o_check_crawling_rate,
	'today-docs-crawled'	=> \$o_check_today_docs_crawled,
	'doc-errors'			=> \$o_check_doc_errors,
	'docs-found'			=> \$o_check_docs_found,
	'qpm'					=> \$o_check_qpm,
	
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

if ( $o_check_crawl ){
	$result = $session->get_request(-varbindlist => [ $crawlRunning ],);
	if (! defined($result) ) {
		printf "ERROR: %s.\n", $session->error();
		$session->close();
		exit $ERRORS{UNKNOWN};
	}
	if ( $result->{$crawlRunning} == 1 ){
		$output = "Crawl is running";
		$perfs = "crawl_is_running=".$result->{$crawlRunning}.";;;;"
	}
	elsif ( $result->{$crawlRunning} == 0 ){
		$output = "Crawl is paused";
		$perfs = "crawl_is_running=".$result->{$crawlRunning}.";;;;"
	}
	else {
		# What ??
		$output = "Don't know this crawl state : ".$result->{$crawlRunning};
		$exit_code = "UNKNOWN";
	}
}
elsif ( $o_check_disk_health or $o_check_temperature_health or $o_check_machine_health){
	my $oid_status = undef;
	my $oid_errors = undef;
	if ( $o_check_disk_health ){
		$oid_status = $diskHealth;
		$oid_errors = $diskErrors;
		$output = "Disk(s) is ";
	}
	elsif ( $o_check_temperature_health ){
		$oid_status = $temperatureHealth;
		$oid_errors = $temperatureErrors;
		$output = "Temperature is ";
	}
	elsif ( $machineHealth ){
		$oid_status = $machineHealth;
		$oid_errors = $machineErrors;
		$output = "Machine is ";
	}
	$result = $session->get_request(-varbindlist => [ $oid_status ],);
	if (! defined($result) ) {
		printf "ERROR: %s.\n", $session->error();
		$session->close();
		exit $ERRORS{UNKNOWN};
	}
	$output .= $health_states{$result->{$oid_status}}{STATE};
	$exit_code = $health_states{$result->{$oid_status}}{NAGIOS_STATE};
	if ( $health_states{$result->{$oid_status}}{STATE} ne "green" ){
		# Get errors
		$result2 = $session->get_request(-varbindlist => [ $oid_errors  ],);
		if (! defined($result2) ) {
			printf "ERROR: %s.\n", $session->error();
			$session->close();
			exit $ERRORS{UNKNOWN};
		}
		$output .= " - Errors: ".$result2->{$oid_errors};
	}
}
elsif ( $o_check_docs_served or $o_check_crawling_rate or $o_check_today_docs_crawled or $o_check_doc_errors or $o_check_docs_found or $o_check_qpm ){
	my $oid = undef;
	if ( $o_check_docs_served ){
		$oid = $docsServed;
		$output = "Number of documents being served: ";
		$perfs = "docs_served=";
	}
	elsif ( $o_check_crawling_rate ){
		$oid = $crawlingRate;
		$output = "Current crawling rate: ";
		$perfs = "crawling_rate=";
	}
	elsif ( $o_check_today_docs_crawled ){
		$oid = $todayDocsCrawled;
		$output = "number of documents crawled today: ";
		$perfs = "docs_crawled=";
	}
	elsif ( $o_check_doc_errors ){
		$oid = $docErrors;
		$output = "Number of times an error occurred while trying to crawl a document: ";
		$perfs = "doc_errors=";
	}
	elsif ( $o_check_docs_found ){
		$oid = $docsFound;
		$output = "Total documents found: ";
		$perfs = "docs_founds=";
	}
	if ( $o_check_qpm ){
		$oid = $qpm;
		$output = "Queries per minute being handled: ";
		$perfs = "queries=";
	}
	$result = $session->get_request(-varbindlist => [ $oid ],);
	if (! defined($result) ) {
		printf "ERROR: %s.\n", $session->error();
		$session->close();
		exit $ERRORS{UNKNOWN};
	}
	$output .= $result->{$oid};
	$perfs .= $result->{$oid}.";;;;";
	# If threshold are defined, get plugin status
	if ( $o_crit_opt and ($result->{$oid} >= $o_crit_opt) ){
		$exit_code = "CRITICAL";
	}
	elsif ( $o_warn_opt and ($result->{$oid} >= $o_warn_opt) ){
		$exit_code = "WARNING";
	}
}
else {
	# Welcome in the twilight zone....
	print "Don't know this option...\n";
	help();
	exit $ERRORS{UNKNOWN};
}
$session->close();
print "$exit_code - $output | $perfs\n";
exit $ERRORS{$exit_code};


