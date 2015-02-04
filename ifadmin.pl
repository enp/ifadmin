#!/usr/bin/env perl

use Modern::Perl;

use POSIX;

use File::Basename qw(dirname);
use File::Path qw(rmtree);

use NetSNMP::agent (':all');
use NetSNMP::ASN qw(ASN_INTEGER);

use Net::Netconf::Manager;
use XML::Fast;
use XML::Tidy;

use Data::Dump;

use constant ifAdminStatus => '.1.3.6.1.2.1.2.2.1.7';

$SIG{CHLD} = "IGNORE";

my $caller = caller();
my %conf;
my $ncf;

sub readconf {
    my $conf = dirname(__FILE__).'/ifadmin.conf';
    open(FILE, "<$conf") or die "Can't open configuration file $conf : $!";
    my @lines = <FILE>;
    close(FILE);
        foreach (@lines) {
        chomp;      # no newline
        s/#.*//;    # no comments
        s/^\s+//;   # no leading white
        s/\s+$//;   # no trailing white
        next unless length; # anything left?
        my @items = split(/\s+/, $_);
        $conf{$items[0]} = $items[1];
    }
}

sub netconf {
    $ncf = new Net::Netconf::Manager(
        'access' => 'ssh',
        'login' => $conf{'login'},
        'password' => $conf{'password'},
        'hostname' => $conf{'hostname'},
        'do_not_connect' => 1
    );
}

sub dumpxml {
    my $ncf = shift;
    my $session = $ncf->get_session_id();
    my $dumpdir = $conf{'dumpdir'}."/$session";
    mkdir($dumpdir);
    my $id = xml2hash($ncf->{'request'})->{'rpc'}{'-message-id'};
    my $dumpfile = "$dumpdir/${id}.xml";
    open(FILE, ">$dumpfile") or die "Can't open dump file $dumpfile : $!";
    my $xml = '<message>'.$ncf->{'request'}.$ncf->{'server_response'}.'</message>';
    $xml =~ s/\n//g;
    my $tidy = XML::Tidy->new(xml => $xml);
    $tidy->tidy();
    say FILE $tidy->toString();
    close(FILE);
    return "${session}::${id}";
}

sub get_interface {
    my $index = shift or die "Empty interface index";
    $ncf->connect();
    $ncf->get_interface_information('terse' => '', 'snmp-index' => $index);
    my $id = dumpxml($ncf);
    if ($ncf->has_error()) {
        die "Can't get interface ($index) information [$id] : ".$ncf->get_first_error()->{'error_message'};
    } else {
        my $answer = xml2hash($ncf->{'server_response'});
        my $info = $answer->{'rpc-reply'}{'interface-information'};
        if ($info->{'#text'}) {
            die "Wrong interface ($index) information [$id] : ".$info->{'#text'};
        } else {
            my $interface = $info->{'physical-interface'} || $info->{'logical-interface'};
            if ($interface) {
                return ($id, $interface);
            } else {
                die "No physical or logical interface ($index) [ $id ]";
            }
        }
    }
}

sub set_interface {
    my ($name, $unit, $status) = @_;
    die "Empty interface name" unless($name);
    die "Empty interface unit" unless($unit);
    die "Wrong interface status" unless($status and ($status eq 'up' or $status eq 'down'));
    my $disabled = '<disable'.($status eq 'up'?' operation="delete"':'').'/>';
    my @dumps;
    $ncf->connect();
    $ncf->lock_config(target => 'candidate');
    my $id = dumpxml($ncf);
    push @dumps, $id;
    if ($ncf->has_error()) {
        die "Can't lock config ($name) [ $id ] : ".$ncf->get_first_error()->{'error_message'};
    } else {
        $ncf->edit_config(
            target => 'candidate',
            config => "<configuration>
                         <interfaces>
                           <interface>
                             <name>$name</name>
                             <unit>
                               <name>$unit</name>
                               $disabled
                             </unit>
                           </interface>
                         </interfaces>
                       </configuration>"
        );
        my $id = dumpxml($ncf);
        push @dumps, $id;
        if ($ncf->has_error()) {
            die "Can't edit config ($name) [ ".join(', ',@dumps)." ] : ".$ncf->get_first_error()->{'error_message'};
            $ncf->unlock();
        } else {
            $ncf->commit();
            $id = dumpxml($ncf);
            push @dumps, $id;
            if ($ncf->has_error()) {
                die "Can't commit config ($name) [ ".join(', ',@dumps)." ] : ".$ncf->get_first_error()->{'error_message'};
                $ncf->discard_changes();
                $ncf->unlock();
            }
        }
    }
    return \@dumps;
}

sub debug {
    my $message = shift;
    if ($caller) {
        my $logfile = $conf{'logfile'};
        open(FILE, ">>$logfile") or die "Can't open log file $logfile : $!";
        say FILE strftime("%F %T",localtime())." $message";
        close(FILE);
    } else {
        say $message;
    }
}

sub get {
    my $index = shift;
    eval {
        my ($dump, $interface) = get_interface($index);
        my $name = $interface->{'name'};
        my $value = $interface->{'admin-status'};
        debug("GET index [$index] => $name : [ $dump ] => $value");
        my %status = ( 'up' => '1', 'down' => '2' );
        return $status{$value};
    } or do {
        debug("GET index [$index] => $@");
        return 0;
    };
}

sub set {
    my ($index, $status) = @_;
    if (!defined($caller) or ($caller and fork() == 0)) {
      my %status = ( 1 => 'up', 2 => 'down' );
      my @dumps;
      eval {
          netconf() if ($caller);
          my ($dump, $interface) = get_interface($index);
          push @dumps, $dump;
          my ($name, $unit) = split(/\./,$interface->{'name'});
          my $dumps = set_interface($name, $unit, $status{$status});
          push @dumps, @$dumps;
          debug("SET index [$index] ($status{$status}) => $name.$unit : [ ".join(', ',@dumps)." ]");
      } or do {
          debug("SET index [$index] ($status{$status}) => $@");
      };
      exit() if ($caller);
    }
    return 0;
}

sub handler {
    my ($handler, $registration_info, $request_info, $requests) = @_;
    for(my $request = $requests; $request; $request = $request->next()) {
        my @elements = $request->getOID()->to_array();
        my $size = scalar @elements;
        my $index = $elements[-1];
        if ($size == 11 && $index > 0) {
            if ($request_info->getMode() == MODE_GET) {
                $request->setValue(ASN_INTEGER, get($index));
            } elsif ($request_info->getMode() == MODE_SET_COMMIT) {
                set($index, $request->getValue());
            }
        } else {
            debug("Wrong size [$size] or index [$index]");
        }
    }
}

readconf();
netconf();

if ($caller) {

    new NetSNMP::agent()->register('ifAdminStatus', ifAdminStatus, \&handler);

} else {

    if ($#ARGV > 0) {
        my $operation = shift;
        eval {
            my $code = \&$operation;
            my $data = $code->(@ARGV);
            debug("$operation result : ".Data::Dump::dump($data));
        } or do {
            debug("$operation error : $@");
        };
    } else {
        debug("Usage: $0 <operation> <index> [<value>]");
    }

}
