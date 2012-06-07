#!/usr/bin/perl
#
# GPGlist -- Encrypted alias lists
#
# Programmed by Bastian Ballmann
# E-Mail: Crazydj@chaostal.de
# Web: http://www.datenterrorist.de
#
# Based on the code of Francisco Jesus Monserrat Coll
# http://www.rediris.es/app/pgplist/index.en.html
# But it's a complete rewrite from scratch.
#
# Last update: 29.01.2005
#
# This program is free software; you can redistribute
# it and/or modify it under the terms of the
# GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will
# be useful, but WITHOUT ANY WARRANTY; without even
# the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.


###[ Loading modules ]###

use XML::Simple;
use File::Copy;
use strict;
use locale;


###[ Config ]###

my $config = "/etc/gpglist.conf";


###[ MAIN PART ]###

# Didn't get it?
usage() unless defined $ARGV[0];
usage() if $ARGV[0] eq "--help";

# Create or delete something?
#create_list() if $ARGV[0] eq "--new";
#delete_list() if $ARGV[0] eq "--del";

# Set secure umask
umask(066);

# Set important environment variables
$ENV{'PATH'} = '';
$ENV{'BASH_ENV'} = '';
$ENV{'IFS'} = '\r\n';

# Read config
my $listname = $ARGV[0];
$config = $ARGV[1] if defined $ARGV[1];
my $cfg = XMLin($config, ForceArray => ['member']) or die "Cannot read config file $config!\n$!\n";

my $logfile = $cfg->{'lists'}->{$listname}->{'logfile'};
my $listaddr = $cfg->{'lists'}->{$listname}->{'address'};
my $keydir = $cfg->{'lists'}->{$listname}->{'keydir'};
my $backupdir = $cfg->{'lists'}->{$listname}->{'backup'};

# Open logfile for appending
open(LOG,">>$logfile") or die "Cannot write to logfile $logfile!\n$!\n";

# Read in the mail
my @email = <STDIN>;

# Do some checks
log_and_exit("List address does not exist!\n") unless defined $listaddr;
log_and_exit("GPG executable is undefined!\n") unless defined $cfg->{'gpg'};
log_and_exit("Keydir of list is undefined!\n") unless defined $keydir;
log_and_exit("Backup directory of list is undefined!\n") unless defined $backupdir;
log_and_exit("Tmpdir is undefined!\n") unless defined $cfg->{'tmpdir'};
log_and_exit("No members found!\n") unless defined $cfg->{'lists'}->{$listname}->{'member'};

# Header and body of the mail are seperated through two new lines
my $email = join("",@email);
my ($head,$body) = split(/\n\n/,$email);

# Save standard header values
my ($to, $cc, $from, $subject);

# Detect loops
my $loop = 0;

# Examine header line by line
my @head = split(/\n/,$head);

foreach my $line (@head)
{
    # We're looping somehow >.<
    $loop = 1 if($line =~ /^X-Loop:\s+(.*)/);

    # Grep standard values
    $to = $1 if ($line =~ /^To:\s+(.*)/);
    $cc = $1 if ($line =~ /^Cc:\s+(.*)/);
    $subject = $1 if ($line =~ /^Subject:\s+(.*)/);
    $from = $1 if ($line =~ /^From:\s+(.*)/);
}

chomp $to if ($to ne "");
chomp $cc if ($cc ne "");
chomp $subject  if ($subject ne "");
chomp $from if ($from ne "");

# Exit on looping
log_and_exit("Loop detected from $from subject $subject.\nExiting.\n") if($loop);

# Got a postmaster reply. Exit.
log_and_exit("Postmaster reply! Subject $subject\n") if($from =~ /mailer-daemon\@/);

# Ok. Let's process the mail
print LOG localtime(time) . " Received message from $from\n";

# Write the encrypted mail to disk
my $encrypted = get_tmpfile($cfg->{'tmpdir'});
open(ENC,">$encrypted") or log_and_exit("Cannot write encrypted mail file $encrypted!\n$!\n");
print ENC $email;
close(ENC);

# Decrypt the message
my $decrypted = get_tmpfile($cfg->{'tmpdir'});
system("$cfg->{'gpg'} --homedir $keydir < $encrypted > $decrypted 2> /dev/null");
open(GPG,"<$decrypted") or log_and_exit("Cannot read $decrypted!\n$!\n");
my @decrypted = <GPG>;
close(GPG);

# Mail was not encrypted!
if(scalar(@decrypted) == 0)
{
    # MUST mails to this list be encrypted?
    if($cfg->{'lists'}->{$listname}->{'encrypted'})
    {
	mail_and_exit("Error! Mail was not encrypted!\n");
    }
    else
    {
	print LOG localtime(time) . "Mail was ok encrypted, but that's ok for this list.\n";
	move($encrypted,$decrypted);
    }
}

# Delete encrypted mail
unlink($encrypted) if((!$cfg->{'lists'}->{$listname}->{'debug'}) && (-e $encrypted));
print LOG localtime(time) . " Decrypted message.\n";

# Encrypt the mail for each member of the list and send it
foreach my $member (@{$cfg->{'lists'}->{$listname}->{'member'}})
{
    # Encrypt mail
    my $encrypted = get_tmpfile($cfg->{'tmpdir'});
    system("$cfg->{'gpg'} -seat --homedir $keydir --batch --yes --always-trust -r $member->{'keyid'} < $decrypted > $encrypted 2> /dev/null");

    # Read encrypted mail
    open(MSG,"<$encrypted") or log_and_exit("Cannot read encrypted mail $encrypted!\n$!\n");
    my $msg = join("", <MSG>);
    close(MSG);

    # Delete encrypted mail
    unlink($encrypted) unless $cfg->{'lists'}->{$listname}->{'debug'};
    print LOG localtime(time) . " Encrypted mail for $member->{'keyid'} $member->{'address'}\n";

    my $header = "";
    my $boundary="=_encrypted-message-" . int(rand(time ^ $$));

    # Modify old header
    for(@head)
    {	
        next if $_ =~ /^\s*boundary=/i;
        next if $_ =~ /^\s*protocol=/i;
        next if $_ =~ /^Content-Transfer-Encoding:/i;

	# Set content type!
	# PGP encrypted mail
	if($_ =~ /^Content-Type:/i)
	{
	    $header .= "Content-Type: multipart/encrypted; boundary=\"$boundary\"\; protocol=\"application/pgp-encrypted\"\n";
	}
	else
	{
	    $header .= "$_\n";
	}
    }

    # Append PGP start mark
    $header .=<<EOF;

This is a MIME GnuPG-encrypted message.  If you see this text, it means
that your E-mail or Usenet software does not support MIME encrypted messages.

--$boundary
Content-Type: application/pgp-encrypted
Content-Transfer-Encoding: 7bit

Version: 1

--$boundary
Content-Type: application/octet-stream
Content-Transfer-Encoding: 7bit

EOF
;

# Mail end mark
my $end=<<EOF;

--$boundary--
EOF
;
    
    # Send the encrypted mail
    mail($listaddr, $member->{'address'}, $header . $msg . $end);
}

# Last but not least remove decrypted mail
unlink($decrypted) unless $cfg->{'lists'}->{$listname}->{'debug'};



###[ Subroutines ]###

# Send a mail
sub mail
{
    my ($from, $to, $msg) = @_;

    print LOG localtime(time) . " Sending mail to $to.\n";

    open(MAIL,"| $cfg->{'sendmail'} -bs 2>/dev/null 1>/dev/null") or die "sendmail error $!\n";
    print MAIL <<EOT;
helo du.da
mail from: $from
rcpt to: $to
data
$msg
.
EOT
;
    close(MAIL);
}


# Create a secure temp file
sub get_tmpfile
{
    my $dir = shift;
    my $file = $dir . "/gpglist" . int(rand(time ^ $$));
    get_tmpfile($dir) if -e $file;
    return $file;
}


# Send mail to sender, log a message, delete temp files and exit
sub mail_and_exit
{
    my $msg = shift;

    $from = $1 if($from =~ /\<(.*)\>/);

    my $header = <<EOM;
From: $listaddr
To: $from
Subject: Error! Mail was rejected!

EOM
;

    mail($listaddr, $from, $header . $msg);
    print LOG localtime(time) . " $msg";

    if(-e $decrypted)
    {
	unlink($decrypted) unless $cfg->{'lists'}->{$listname}->{'debug'};
    }

    if(-e $encrypted)
    {
	unlink($encrypted) unless $cfg->{'lists'}->{$listname}->{'debug'};
    }

    exit(0);
}


# Log a message, backup encrypted mail, delete temp files and exit
sub log_and_exit
{
    my $msg = shift;
    my $backup = get_tmpfile($backupdir);

    print LOG localtime(time) . " $msg";
    print LOG localtime(time) . " Saving mail to $backup\n";
    close(LOG);

    open(OUT,">$backup") or die "Cannot write to $backup!\n$!\n";
    map { print OUT; } @email;
    close(OUT);

    if(-e $decrypted)
    {
	unlink($decrypted) unless $cfg->{'lists'}->{$listname}->{'debug'};
    }

    if(-e $encrypted)
    {
	unlink($encrypted) unless $cfg->{'lists'}->{$listname}->{'debug'};
    }

    exit(0);
}


# Write our XML config file
sub write_config
{
    open(OUT,">$config") or log_and_exit("Cannot write config to $config!\n$!\n");

    print OUT "<?xml version=\"1.0\" ?>\n";
    print OUT "<config>\n";
    
    print OUT "  <gpg>$cfg->{'gpg'}</gpg>\n";
    print OUT "  <sendmail>$cfg->{'sendmail'}</sendmail>\n";
    print OUT "  <tmpdir>$cfg->{'tmpdir'}</tmpdir>\n";
    
    print OUT "\n  <lists>\n\n";
    
    while(my ($list, $config) = each %{$cfg->{'lists'}})
    {
	print OUT "    <$list>\n";
	print OUT "      <address>$config->{'address'}</address>\n";
	print OUT "      <keydir>$config->{'keydir'}</keydir>\n";
	print OUT "      <backup>$config->{'backup'}</backup>\n";
	print OUT "      <logfile>$config->{'logfile'}</logfile>\n";
	print OUT "      <debug>$config->{'debug'}</debug>\n";
	
	foreach my $member (@{$config->{'member'}})
	{
	    print OUT "      <member>\n";
	    print OUT "        <keyid>$member->{'keyid'}</keyid>\n";      
	    print OUT "        <address>$member->{'address'}</address>\n";      
	    print OUT "      </member>\n";
	}
	
	print OUT "    </$list>\n";
    }
    
    print OUT "\n  </lists>\n";
    print OUT "</config>\n";
    close(OUT);
}


# Create a new mailinglist
sub create_list
{
    print "Tell me the name of the list: ";
    my $name = <STDIN>;
    chomp $name;

    print "Address: ";
    $cfg->{'lists'}->{$name}->{'address'} = <STDIN>;
    chomp $cfg->{'lists'}->{$name}->{'address'};

    print "Logfile: ";
    $cfg->{'lists'}->{$name}->{'logfile'} = <STDIN>;
    chomp $cfg->{'lists'}->{$name}->{'logfile'};    

    print "Backup: ";
    $cfg->{'lists'}->{$name}->{'backup'} = <STDIN>;
    chomp $cfg->{'lists'}->{$name}->{'backup'};    

    print "Keydir: ";
    $cfg->{'lists'}->{$name}->{'keydir'} = <STDIN>;
    chomp $cfg->{'lists'}->{$name}->{'keydir'};

    # Check if keydir exists?
    unless(-e $cfg->{'lists'}->{$name}->{'keydir'})
    {
	mkdir($cfg->{'lists'}->{$name}->{'keydir'});

	print "Generating gpg key ring...\n";
	system("$cfg->{'gpg'} --homedir $cfg->{'lists'}->{$name}->{'keydir'} --gen-key");
    }

    print "Writing new config...\n";
    write_config();

    print "Ok. All done so far.\n";
    print "Now edit $config and add the members of the list!\n";
    exit(0);
}


# Delete a mailinglist
sub delete_list
{
    print "Not yet implemented.\n";
    exit(0);
}


# Print usage of this piece of software
sub usage
{
    print "GPGlist -- GPG encrypted alias lists\n";
    print "------------------------------------\n\n";
    print "Usage: $0 <list> [config]\n";
#    print "--new to create a new list\n";
#    print "--del to delete a list\n";
    print "--help to show this text\n";
    print "\n";
    exit(0);
}

# EOF
