use strict;
use warnings;
use utf8;

use Isu4Qualifier::Web;
use Parallel::Async;
use List::Util qw/reduce/;

my $config = Isu4Qualifier::Web->config;

# init redis
Isu4Qualifier::Web->redis->flushall();

my $noop = sub {};

my @tasks;
push @tasks => async {
    # init user_login_last_failure_count (redis)
    my $redis  = Isu4Qualifier::Web->redis;
    my $db     = Isu4Qualifier::Web::db({}); ## hack

    my %last_failure_count = @{
        $db->selectcol_arrayref(
            'SELECT user_id, last_failure_count FROM user_login_last_failure_count',
            { Columns => [1, 2] }
        )
    };
    for my $user_id (keys %last_failure_count) {
        $redis->set("user_login_last_failure_count:$user_id", $last_failure_count{$user_id}, $noop);
        if ($last_failure_count{$user_id} >= $config->{user_lock_threshold}) {
            $redis->sadd(locked_user => $user_id)
        }
    }
    $redis->wait_all_responses;
};

push @tasks => async {
    # init user_login_last_failure_count (redis)
    my $redis  = Isu4Qualifier::Web->redis;
    my $db     = Isu4Qualifier::Web::db({}); ## hack

    my %last_failure_count = @{
        $db->selectcol_arrayref(
            'SELECT ip, last_failure_count FROM ip_login_last_failure_count',
            { Columns => [1, 2] }
        )
    };
    for my $ip (keys %last_failure_count) {
        $redis->set("ip_login_last_failure_count:$ip", $last_failure_count{$ip}, $noop);
        if ($last_failure_count{$ip} >= $config->{ip_ban_threshold}) {
            $redis->sadd(banned_ip => $ip);
        }
    }
    $redis->wait_all_responses;
};

my $task = reduce { $a->join($b) } @tasks;
$task->recv;
