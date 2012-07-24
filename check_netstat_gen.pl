#!/usr/bin/perl -w
#
# ============================== SUMMARY =====================================
#
# Program : check_netstat_gen.pl
# Version : 1.0
# Date    : 01/10/2012
# Authors : piscitelli.david@gmail.com
#           
# Licence : GPL - summary below, full text at http://www.fsf.org/licenses/gpl.txt
#
# =========================== PROGRAM LICENSE =================================
# check_netstat_gen.pl, 
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
#
#
# ======================= VERSIONS and CHANGE HISTORY =========================
# Version 1.0: Initial release
#
# ========================== START OF PROGRAM CODE ===========================
use strict;
use Getopt::Long;
use Data::Dumper;

################################
# GLOBAL VARIABLES
# ... I know, I'm a bad boy :p
my %ERRORS=('OK'=>0,'WARNING'=>1,'CRITICAL'=>2,'UNKNOWN'=>3);
my $VERSION = "1.0";


my $o_verb = 0;
my $o_help = 0;
my $o_crit = undef;
my $o_warn = undef;
my $o_port = "";
my $o_state = "";
my $o_label = undef;
my $o_unit = undef;
my $o_distinct = 0;
my $o_remote = 0;
my $o_version = 0;
my $o_netstat_bin = undef;
my $o_is_listen = 0;
my $o_connections = 0;
# 
Getopt::Long::Configure ("bundling");
GetOptions(
		'v'     		=> \$o_version,         'version'      	=> \$o_version,
        'd'     		=> \$o_verb,            'debug'       	=> \$o_verb,
        'h'     		=> \$o_help,            'help'          => \$o_help,
        'c:s'   		=> \$o_crit,            'critical:s'    => \$o_crit,
        'w:s'   		=> \$o_warn,            'warning:s'     => \$o_warn,
		'p:s'			=> \$o_port,			'port:s'		=> \$o_port,
		's:s'			=> \$o_state,			'state:s'		=> \$o_state,
		'l:s'			=> \$o_label,			'label:s'		=> \$o_label,
		'D'				=> \$o_distinct,		'distinct'		=> \$o_distinct,
		'R'				=> \$o_remote,			'remote'		=> \$o_remote,
		'netstat-bin:s'	=> \$o_netstat_bin,
		'is-listen'		=> \$o_is_listen,
		'connections'	=> \$o_connections,
    );

####################################################################
# LES FONCTIONS
####################################################################
    
sub help {
   print <<EOT;



EOT
}

# Defi
sub get_states_to_catch {
	my $states_to_catch = shift;
	
	# Define all states
	my %hash_all_states = ( ESTABLISHED => 0, 
							SYN_SENT => 0,
							SYN_RECV => 0,
							FIN_WAIT1 => 0,
							FIN_WAIT2 => 0,
							TIME_WAIT => 0,
							CLOSED => 0,
							CLOSE_WAIT => 0,
							LAST_ACK => 0,
							LISTEN => 0,
							CLOSING => 0,
							UNKNOWN => 0
	);
	if ( $states_to_catch eq "ALL" ){
		foreach my $state (keys %hash_all_states) {
			$hash_all_states{$state} = 1;
		}
	}
	else {
		my @tmp = split /,/, $states_to_catch;
		foreach my $argument_state (@tmp) {
			if ( exists($hash_all_states{$argument_state}) ){
				$hash_all_states{$argument_state} = 1;
			}
		}
	}
	return %hash_all_states;
}

# Check thresholds
sub thresholds_is_ok {
	my $value = shift;
	my $threshold = shift;
	
	my $code = 1;
	
	if ( ($threshold =~ m/^(\d+)$/) and ($value>=$1) ){ $code = 0; }
	elsif ( ($threshold =~ m/^:(\d+)$/) and ($value>=$1) ){ $code = 0; }
	elsif ( ($threshold =~ m/^(\d+):$/) and ($value<=$1) ){ $code = 0; }
	elsif ( ($threshold =~ m/^(\d+):(\d+)$/) and (($value>=$1) or ($value<=$2)) ){ $code = 0; }
	return $code;
}

# Get the different components of netstat command output
sub get_netstat_data {
	my $os = shift;
	my $output = shift;
	my $debug = shift;
	
	my @netstat_data = ();
	my $line = "";
	my $source = "";
	my $dest = "";
	my $state = "";
	my ($adr_src,$port_src) = ();
	my ($adr_dest,$port_dest) = ();
	
	foreach $line (@$output) {
		chomp $line;
		#print "Netstat command output line = $line\n" if $debug;
		if ( ($os eq "AIX") and ($line =~ m/^(tcp|udp)\d*\s*\d+\s+\d+\s+(\S+)\.([0-9]+)\s+(\S+)\.([0-9*]+)\s+(\w*)/) ) {
			($adr_src,$port_src) = ($2,$3);
			($adr_dest,$port_dest) = ($4,$5);
			if ( $1 eq "tcp" ){
				$state = $6;
			}
			else {
				# Special state for UDP daemons
				$state = "LISTEN_UDP";
			}
			print "Matched :: Source: $adr_src,$port_src, Dest: $adr_dest,$port_dest, State: $state\n\n" if $debug;
			push @netstat_data, { ADRSRC => $adr_src, PORTSRC => $port_src, ADRDEST => $adr_dest, PORTDEST => $port_dest, STATE => $state };
		}
		elsif ( $os eq "SOL" ) {
			if ($line =~ m/^\s*(\S+)\.(\d+)\s+(\S+)\.(\S+)\s+\d+\s+\d+\s+\d+\s+\d+\s+(\w+)/) {
				# Solaris, tcp sockets
				($adr_src,$port_src) = ($1,$2);
				($adr_dest,$port_dest) = ($3,$4);
				$state = $5;
				print "Matched :: Source: $adr_src,$port_src, Dest: $adr_dest,$port_dest, State: $state\n\n" if $debug;
				push @netstat_data, { ADRSRC => $adr_src, PORTSRC => $port_src, ADRDEST => $adr_dest, PORTDEST => $port_dest, STATE => $state };
			}
			elsif ( $line =~ m/^\s*(\S+)\.(\d+)\s+\w+\s*$/ ) {
				# Solaris, udp sockets
				($adr_src,$port_src) = ($1,$2);
				($adr_dest,$port_dest) = (0,0);
				$state = "LISTEN_UDP";
				print "Matched :: Source: $adr_src,$port_src, Dest: $adr_dest,$port_dest, State: $state\n\n" if $debug;
				push @netstat_data, { ADRSRC => $adr_src, PORTSRC => $port_src, ADRDEST => $adr_dest, PORTDEST => $port_dest, STATE => $state };
			}
		}
		elsif ( ($os eq "LINUX") and ($line =~ m/^tcp\d?\s*\d+\s+\d+\s+(\S+)\:(\S+)\s+(\S+)\:(\S+)\s+(\w+)/) ) {
			($adr_src,$port_src) = ($1,$2);
			($adr_dest,$port_dest) = ($3,$4);
			if ( $5 ) {
				$state = $5;
			}
			else {
				# Special state for UDP daemons
				$state = "LISTEN_UDP";
			}	
			print "Matched :: Source: $adr_src,$port_src, Dest: $adr_dest,$port_dest, State: $state\n\n" if $debug;
			push @netstat_data, { ADRSRC => $adr_src, PORTSRC => $port_src, ADRDEST => $adr_dest, PORTDEST => $port_dest, STATE => $state };
		}
	}
	return @netstat_data;
}
    
sub get_connection_numbers {
	my $data		= shift;
	my $ip_reg 		= shift;
	my $port 		= shift;
	my $distinct 	= shift;
	my $states 		= shift;
	my $distant 	= shift;
	my $debug 		= shift;

	my %hash_nb_conn = ();
	my $element = "";
	my %hash_ip = ();
	my $regexp = "";
	my $dont_check_port = 0;
	
	if ( $port eq "ALL" ){
		$dont_check_port = 1;
	}
	foreach my $state (keys %$states){
		$hash_nb_conn{$state} = 0 if ($states->{$state} == 1);
	}
	foreach $element ( @$data ) {
		$regexp = qr/$ip_reg/;
		#print "Regexp=$regexp\n";
		if ( $dont_check_port ){
			$port = $element->{PORTSRC};
		}
		if ( $distant == 0 ){
			# Working on local connections
			if ( ($element->{PORTSRC} eq $port) 
				 and exists($states->{$element->{STATE}}) 
				 and ($states->{$element->{STATE}} == 1) 
				 and ($element->{ADRSRC} =~ m/$regexp/) ) {
				if ( $distinct ){
					if ( not exists($hash_ip{$element->{ADRDEST}}) ){
						$hash_nb_conn{$element->{STATE}}++;
						$hash_ip{$element->{ADRDEST}} = 1;
					}
				}
				else {
					$hash_nb_conn{$element->{STATE}}++;
				}
			}
		}
		else {
			# Working on remote connections
			print "Port=".$element->{PORTDEST}.",port cherche: ".$port.",".$element->{STATE}.",".$states->{$element->{STATE}}.",".$element->{ADRDEST}.",".$regexp."\n";
			if ( ($element->{PORTDEST} eq $port) 
				 and exists($states->{$element->{STATE}}) 
				 and ($states->{$element->{STATE}} == 1) 
				 and ($element->{ADRDEST} =~ m/$regexp/) ) {
				print "trouve !\n";
				if ( $distinct ){
					if ( not exists($hash_ip{$element->{ADRDEST}}) ){
						$hash_nb_conn{$element->{STATE}}++;
						$hash_ip{$element->{ADRDEST}} = 1;
					}
				}
				else {
					$hash_nb_conn{$element->{STATE}}++;
				}
			}
		}
	}
	return %hash_nb_conn;
}


####################################################################
# DECLARATION DES VARIABLES ET PARAMETRES
####################################################################
my $netstat = "";
my $os = "";
my %hash_data_connections = ();
my $var_check = -1;
my $plugin_state = "OK";
my $un_element = "";
my ($output,$perfs) = ("","");
my %hash_stats = ();
my $i = 0;
my $nb = 0;
my %hash_state = ();
my %hash_ports = ();
my %hash_ports_exclude = ();
my %hash_ips = ();
my @output_command = ();
my $cmd = "";
my %hash_states_to_catch = ();
my @list_to_analyse = ();

if ( $o_help ){
	help();
	exit 0;
}

if ( $o_version ){
	print $VERSION."\n";
	exit 0;
}

$o_label = "Connexions" unless $o_label;

unless ( $o_netstat_bin ){
	# Get netstat location from each OS
	$os = `uname -s`;
	if ( $os =~ m/sunos/i ){
		$os = "SOL";
		$netstat = "/usr/bin/netstat";
	}
	elsif ( $os =~ m/linux/i ){
		$os = "LINUX";
		$netstat = "/bin/netstat";
	}
	elsif ( $os =~ m/AIX/i ){
		$os = "AIX";
		$netstat = "/usr/bin/netstat";
	}
	else{
		print "Systeme \"$os\" inconnu\n";
		exit $ERRORS{UNKNOWN};
	}
}

$os = "AIX";

####################################################################
# MAIN
####################################################################

#### DEFAULT VALUES

# Get the netstat command
if ( $os eq "SOL" ){
	$cmd = "$netstat -anf inet && $netstat -anf inet6";
}
elsif ( $os eq "LINUX" ){
	$cmd = "$netstat -an --tcp && $netstat -an --udp";
}
elsif ( $os eq "AIX" ){
	$cmd = "$netstat -anf inet";
}
else {
	print "Unknown system \"$os\"\n";
	exit $ERRORS{UNKNOWN};
}

# On lance la commande
print "Command  = $cmd\n" if $o_verb;
#@output_command = `$cmd 2>&1`;
@output_command = `cat sortie_netstat_aix.txt 2>&1`;
#print @output_command;
if ( ($?>>8) != 0 ){
	print "Error while executing command... ($?)\n";
	exit $ERRORS{'UNKNOWN'};
}
my @netstat_data = get_netstat_data($os,\@output_command,$o_verb);
if ( not $o_is_listen and not $o_connections and not $o_port){
	if ( not $o_state ){
		# Get All States
		%hash_states_to_catch = get_states_to_catch("ALL");
	}
	else {
		%hash_states_to_catch = get_states_to_catch($o_state);
	}
	%hash_data_connections	= get_connection_numbers(\@netstat_data,'.*',"ALL",$o_distinct,\%hash_states_to_catch,$o_remote,$o_verb);	
	foreach my $data (keys %hash_data_connections ){
		if ( $o_crit and not thresholds_is_ok($hash_data_connections{$data},$o_crit) ) {
			$output .= "$data=$hash_data_connections{$data}(CRITICAL), ";
			$plugin_state = "CRITICAL";
		}
		elsif ( $o_warn and not thresholds_is_ok($hash_data_connections{$data},$o_warn) ) {
			$output .= "$data=$hash_data_connections{$data}(WARNING), ";
			$plugin_state = "WARNING" if $plugin_state eq "OK";
		}
		else {
			$output .= "$data=$hash_data_connections{$data}(OK), ";
		}
		my $tmp = lc $data;
		$perfs .= "'".$tmp."'=".$hash_data_connections{$data}.";;;; ";
	}
}
elsif ( $o_port ) {
	my @tmp = split /,/, $o_port;
	my ($ip,$port) = (undef,undef);
	foreach my $elem (@tmp) {
		if ( $elem =~ m/(\S*):(\d+)/ ){
			$ip = $1;
			$port = $2;
			if ( not $ip ){
				# If IP is not specified, then check all ips
				$ip = ".*";
			}
			else {
				# Somme substitutions to contruct regexp to find
				$ip =~ s/\./\\./g;
				$ip =~ s/\*/.*/g;
			}
			push @list_to_analyse, { STRING => $elem, IP => $ip, PORT => $port };
		}
	}
	if ( $o_is_listen ){
		# Search for LISTEN in tcp protocol and virtual LISTEN_UDP for udp protocol
		$o_state = "LISTEN";
		%hash_states_to_catch = get_states_to_catch($o_state);
		# Add special state for UDP (invented by me)
		$hash_states_to_catch{LISTEN_UDP} = 1;
	}
	elsif ( $o_connections ){
		$o_state = "ESTABLISHED";
		%hash_states_to_catch = get_states_to_catch($o_state);
	}
	elsif ( $o_state ){
		%hash_states_to_catch = get_states_to_catch($o_state);
	}
	else {
		%hash_states_to_catch = get_states_to_catch("ALL");
	}
	foreach my $to_analyse ( @list_to_analyse ){
		%hash_data_connections	= get_connection_numbers(\@netstat_data,$to_analyse->{'IP'},$to_analyse->{'PORT'},$o_distinct,\%hash_states_to_catch,$o_remote,$o_verb);
		%{ $to_analyse->{'RESULT'} } = %hash_data_connections;
	}	
}

#print Dumper(@list_to_analyse);

# We have data, now let nagios-ize this stuff....
# First, format output
# If check LISTEN states
if ( $o_is_listen ){
	$o_label = "Controle des sockets";
	foreach my $to_analyse ( @list_to_analyse ){
		if ( $to_analyse->{RESULT}{LISTEN} > 0 ){
			$output .=  "TCP:".$to_analyse->{STRING}." est a l'ecoute, ";
		}
		elsif ( $to_analyse->{RESULT}{LISTEN_UDP} > 0 ){
			$output .=  "UDP:".$to_analyse->{STRING}." est a l'ecoute, ";
		}
		else {
			# No one is listenig on this port with this (those) IP(s)
			$output .=  $to_analyse->{STRING}." n'est pas a l'ecoute, ";
			$plugin_state = "CRITICAL";
		}
	}
}
else {
	$o_label = "Nombre de connexions";
	foreach my $to_analyse ( @list_to_analyse ){
		foreach my $state ( keys %{$to_analyse->{RESULT}} ){
			if ( $o_crit and not thresholds_is_ok($to_analyse->{RESULT}{$state},$o_crit) ) {
				$output .= "TCP".$to_analyse->{STRING}.":".$state."=".$to_analyse->{RESULT}{$state}."(CRITICAL), ";
				$plugin_state = "CRITICAL";
			}
			elsif ( $o_warn and not thresholds_is_ok($to_analyse->{RESULT}{$state},$o_warn) ) {
				$output .= "TCP".$to_analyse->{STRING}.":".$state."=".$to_analyse->{RESULT}{$state}."(WARNING), ";
				$plugin_state = "WARNING" if $plugin_state eq "OK";
			}
			else {
				$output .= "TCP".$to_analyse->{STRING}.":".$state."=".$to_analyse->{RESULT}{$state}."(OK), ";
			}
			my $tmp = lc $state;
			$perfs .= "'tcp_".$to_analyse->{STRING}."_".$tmp."'=".$to_analyse->{RESULT}{$state}.";;;; ";	
		}
	}
}


print "$plugin_state - $o_label : $output | $perfs\n";
exit $ERRORS{$plugin_state};


	
