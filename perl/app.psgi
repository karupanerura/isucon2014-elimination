use FindBin;
use lib "$FindBin::Bin/extlib/lib/perl5";
use lib "$FindBin::Bin/lib";
use File::Basename;
use Plack::Builder;
use Isu4Qualifier::Web;

my $root_dir = File::Basename::dirname(__FILE__);

my $app = Isu4Qualifier::Web->psgi($root_dir);
builder {
    enable 'ReverseProxy';
    enable 'Session::Simple',
        store       => Isu4Qualifier::Web->cache,
        cookie_name => 'isu4_session';
    $app;
};
