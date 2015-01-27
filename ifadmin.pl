#!/usr/bin/env perl

use Modern::Perl;

use POSIX;

use NetSNMP::agent (':all');
use NetSNMP::ASN qw(ASN_INTEGER);

use constant ifAdminStatus => '.1.3.6.1.2.1.2.2.1.7';

my %values;

sub debug {
    my $message = shift;
    open my $FILE, ">>", "/tmp/ifadmin.log";
    print $FILE strftime("%F %T",localtime())." $message\n";
    close $FILE;
}

sub handler {
    my ($handler, $registration_info, $request_info, $requests) = @_;
    for(my $request = $requests; $request; $request = $request->next()) {
        my @elements = $request->getOID()->to_array();
        my $size = scalar @elements;
        my $index = $elements[-1];
        if ($size == 11 && $index > 0) {
            if ($request_info->getMode() == MODE_GET) {
                debug("GET index [$index] => ".$values{$index});
                $request->setValue(ASN_INTEGER, $values{$index} || 1);
            } elsif ($request_info->getMode() == MODE_SET_COMMIT) {
                debug("SET index [$index] <= ".$request->getValue());
                $values{$index} = $request->getValue();
            }
        } else {
            debug("Wrong size [$size] or index [$index]");
        }
    }
}

new NetSNMP::agent()->register('ifAdminStatus', ifAdminStatus, \&handler);
