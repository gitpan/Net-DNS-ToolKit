use ExtUtils::MakeMaker;
use Config;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
    'NAME'		=> 'Net::DNS::ToolKit',
    'VERSION_FROM'	=> 'ToolKit.pm', # finds $VERSION
    'PREREQ_PM'		=> {	Net::DNS::Codes	=> 0.06 },
    'LIBS'		=> ['-lresolv'], # e.g., '-lm'
    'depend'		=> {'ToolKit.c'	=> 'ToolKit.h xs_include/dn_expand.inc xs_include/miniSocket.inc',
			},
    'clean'		=> { FILES	=> "*.bs *.o *~ uIxxdefs.h config.log"},
);

sub MY::top_targets {
  package MY;
  my $begin = q|
config  :: uIxxdefs.h
	@$(NOOP)

# siteconf CCname Cfile_ext OBJext EXEext "Cflags" "LDflags"
#
uIxxdefs.h :
	./siteconf "$(CC)" ".c" "$(OBJ_EXT)" "$(EXE_EXT)" "$(CCFLAGS)" "$(LDFLAGS)"
|;
  my $inherited = shift->SUPER::top_targets(@_);
  $inherited =~ s/(pure_all\s+::.+)/$1 README/;
  $begin . $inherited;
}

sub MY::post_constants {
  my $post_constants = q|
MY_POD2TEXT = |. $Config{scriptdirexp} .'/pod2text' .q|   
|;
} 

sub MY::postamble {
  package MY;
  my $postamble = q|
README  : ToolKit.pm
	@$(MY_POD2TEXT) ToolKit.pm > README

|;
}
