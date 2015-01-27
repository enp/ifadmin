#!/usr/bin/env perl

use Modern::Perl;

use POSIX;

use File::Basename qw(dirname);

use NetSNMP::agent (':all');
use NetSNMP::ASN qw(ASN_INTEGER);

use constant ifAdminStatus => '.1.3.6.1.2.1.2.2.1.7';

my %values;
my $caller = caller();
my %conf;

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
    my $value = $values{$index} || 1;
    debug("GET index [$index] => $value");
    return $value;
}

sub set {
    my $index = shift;
    my $value = shift || die "Empty value";
    debug("GET index [$index] => $value");
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

if ($caller) {

    new NetSNMP::agent()->register('ifAdminStatus', ifAdminStatus, \&handler);

} else {

    if ($#ARGV > 0) {
        my $operation = shift;
        eval {
            my $code = \&$operation;
            my $data = $code->(@ARGV);
            debug($data);
        } or do {
            debug("Can't execute $operation : $@");
        };
    } else {
        debug("Usage: $0 <operation> <index> [<value>]");
    }

}
