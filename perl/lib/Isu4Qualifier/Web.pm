package Isu4Qualifier::Web;
use strict;
use warnings;
use utf8;

use Kossy;
use DBIx::Sunny;
use Digest::SHA qw/ sha256_hex /;
use Data::MessagePack;
use Compress::LZ4;
use Cache::Memcached::Fast;

{
    my $config = {
        user_lock_threshold => $ENV{'ISU4_USER_LOCK_THRESHOLD'} || 3,
        ip_ban_threshold    => $ENV{'ISU4_IP_BAN_THRESHOLD'}    || 10,
    };
    sub config { $config }
}

{
    my $msgpack = Data::MessagePack->new->utf8;
    sub _message_pack   { $msgpack->pack(@_)   }
    sub _message_unpack { $msgpack->unpack(@_) }
    sub _compress_lz4   { ${$_[1]} = Compress::LZ4::compress(${$_[0]})   }
    sub _uncompress_lz4 { ${$_[1]} = Compress::LZ4::decompress(${$_[0]}) }

    my $memcached = Cache::Memcached::Fast->new({
        servers            => ['127.0.0.1:11211'],
        serialize_methods  => [\&_message_pack, \&_message_unpack],
        utf8               => 1,
        ketama_points      => 150,
        hash_namespace     => 0,
        compress_threshold => 5_000,
        compress_methods   => [\&_compress_lz4, \&_uncompress_lz4],
    });
    sub cache { $memcached }
}

sub db {
  my ($self) = @_;
  return $self->{_db} //= do {
      my $host     = $ENV{ISU4_DB_HOST} || '127.0.0.1';
      my $port     = $ENV{ISU4_DB_PORT} || 3306;
      my $username = $ENV{ISU4_DB_USER} || 'root';
      my $password = $ENV{ISU4_DB_PASSWORD};
      my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';
      DBIx::Sunny->connect(
          "dbi:mysql:database=$database;host=$host;port=$port", $username, $password, {
              RaiseError => 1,
              PrintError => 0,
              AutoInactiveDestroy => 1,
              mysql_enable_utf8   => 1,
              mysql_auto_reconnect => 1,
          },
      );
  };
}

sub calculate_password_hash {
    my ($password, $salt) = @_;
    sha256_hex($password . ':' . $salt);
};

sub user_locked {
    my ($self, $user) = @_;
    my $log = $self->db->select_row(
        'SELECT COUNT(1) AS failures FROM login_log WHERE user_id = ? AND id > IFNULL((select id from login_log where user_id = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0)',
        $user->{'id'}, $user->{'id'});

    $self->config->{user_lock_threshold} <= $log->{failures};
};

sub ip_banned {
    my ($self, $ip) = @_;
    my $log = $self->db->select_row(
        'SELECT COUNT(1) AS failures FROM login_log WHERE ip = ? AND id > IFNULL((select id from login_log where ip = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0)',
        $ip, $ip);

    $self->config->{ip_ban_threshold} <= $log->{failures};
};

sub attempt_login {
    my ($self, $login, $password, $ip) = @_;
    my $user = $self->db->select_row('SELECT * FROM users WHERE login = ?', $login);

    if ($self->ip_banned($ip)) {
        $self->login_log(0, $login, $ip, $user ? $user->{id} : undef);
        return undef, 'banned';
    }

    if ($self->user_locked($user)) {
        $self->login_log(0, $login, $ip, $user->{id});
        return undef, 'locked';
    }

    if ($user && calculate_password_hash($password, $user->{salt}) eq $user->{password_hash}) {
        $self->login_log(1, $login, $ip, $user->{id});
        return $user, undef;
    }
    elsif ($user) {
        $self->login_log(0, $login, $ip, $user->{id});
        return undef, 'wrong_password';
    }
    else {
        $self->login_log(0, $login, $ip);
        return undef, 'wrong_login';
    }
}

sub current_user {
    my ($self, $user_id) = @_;

    $self->db->select_row('SELECT * FROM users WHERE id = ?', $user_id);
}

sub last_login {
    my ($self, $user_id) = @_;

    my $logs = $self->db->select_all(
        'SELECT * FROM login_log WHERE succeeded = 1 AND user_id = ? ORDER BY id DESC LIMIT 2',
        $user_id);

    @$logs[-1];
}

sub banned_ips {
    my ($self) = @_;
    my @ips; # banned_ips
    my $threshold = $self->config->{ip_ban_threshold};

    # 1) threashold分試したのに、一回も成功したことがないip
    my $not_succeeded = $self->db->select_all('SELECT ip FROM 
        (SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) AS t0
        WHERE
        t0.max_succeeded = 0
        AND
        t0.cnt >= ?', $threshold
    );

    for my $row (@$not_succeeded) {
        push @ips, $row->{ip};
    }

    # 2) 最後にログイン成功してから、ログインを試みた回数が、threashold以上ならダメ
    my $last_succeeds = $self->db->select_all('
        SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip');

    for my $row (@$last_succeeds) {
        my $count = $self->db->select_one('SELECT COUNT(1) AS cnt FROM login_log WHERE ip = ? AND ? < id', $row->{ip}, $row->{last_login_id});
        if ($threshold <= $count) {
            push @ips, $row->{ip};
        }
    }

    \@ips;
}

sub locked_users {
    my ($self) = @_;
    my @user_ids;
    my $threshold = $self->config->{user_lock_threshold};

    my $not_succeeded = $self->db->select_all('SELECT user_id, login FROM (SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY user_id) AS t0 WHERE t0.user_id IS NOT NULL AND t0.max_succeeded = 0 AND t0.cnt >= ?', $threshold);

    for my $row (@$not_succeeded) {
        push @user_ids, $row->{login};
    }

    my $last_succeeds = $self->db->select_all('SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id');

    for my $row (@$last_succeeds) {
        my $count = $self->db->select_one('SELECT COUNT(1) AS cnt FROM login_log WHERE user_id = ? AND ? < id', $row->{user_id}, $row->{last_login_id});
        if ($threshold <= $count) {
            push @user_ids, $row->{login};
        }
    }

    \@user_ids;
}

sub login_log {
    my ($self, $succeeded, $login, $ip, $user_id) = @_;
    $self->db->query(
        'INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) VALUES (NOW(),?,?,?,?)',
        $user_id, $login, $ip, ($succeeded ? 1 : 0)
    );
};

sub set_flash {
    my ($self, $c, $msg) = @_;
    $c->req->env->{'psgix.session'}->{flash} = $msg;
}

sub pop_flash {
    my ($self, $c, $msg) = @_;
    my $flash = $c->req->env->{'psgix.session'}->{flash};
    delete $c->req->env->{'psgix.session'}->{flash};
    $flash;
};

sub render_html_content {
    my ($self, $content) = @_;
    return <<__TEMPLATE__;
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="/stylesheets/bootstrap.min.css">
    <link rel="stylesheet" href="/stylesheets/bootflat.min.css">
    <link rel="stylesheet" href="/stylesheets/isucon-bank.css">
    <title>isucon4</title>
  </head>
  <body>
    <div class="container">
      <h1 id="topbar">
        <a href="/"><img src="/images/isucon-bank.png" alt="いすこん銀行 オンラインバンキングサービス"></a>
      </h1>
$content
    </div>

  </body>
</html>
__TEMPLATE__
}

sub render_html_index {
    my ($self, $flash) = @_;
    my $flash_html = $flash ?
        qq{<div id="notice-message" class="alert alert-danger" role="alert">$flash</div>}:
        q{};
    return $self->render_html_content(<<__TEMPLATE__);
<div id="be-careful-phising" class="panel panel-danger">
  <div class="panel-heading">
    <span class="hikaru-mozi">偽画面にご注意ください！</span>
  </div>
  <div class="panel-body">
    <p>偽のログイン画面を表示しお客様の情報を盗み取ろうとする犯罪が多発しています。</p>
    <p>ログイン直後にダウンロード中や、見知らぬウィンドウが開いた場合、<br>すでにウィルスに感染している場合がございます。即座に取引を中止してください。</p>
    <p>また、残高照会のみなど、必要のない場面で乱数表の入力を求められても、<br>絶対に入力しないでください。</p>
  </div>
</div>

<div class="page-header">
  <h1>ログイン</h1>
</div>

$flash_html

<div class="container">
  <form class="form-horizontal" role="form" action="/login" method="POST">
    <div class="form-group">
      <label for="input-username" class="col-sm-3 control-label">お客様ご契約ID</label>
      <div class="col-sm-9">
        <input id="input-username" type="text" class="form-control" placeholder="半角英数字" name="login">
      </div>
    </div>
    <div class="form-group">
      <label for="input-password" class="col-sm-3 control-label">パスワード</label>
      <div class="col-sm-9">
        <input type="password" class="form-control" id="input-password" name="password" placeholder="半角英数字・記号（２文字以上）">
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-primary btn-lg btn-block">ログイン</button>
      </div>
    </div>
  </form>
</div>

__TEMPLATE__
}

sub render_html_mypage {
    my ($self, $last_login) = @_;
    return $self->render_html_content(<<__TEMPLATE__);
<div class="alert alert-success" role="alert">
  ログインに成功しました。<br>
  未読のお知らせが０件、残っています。
</div>

<dl class="dl-horizontal">
  <dt>前回ログイン</dt>
  <dd id="last-logined-at">$last_login->{created_at}</dd>
  <dt>最終ログインIPアドレス</dt>
  <dd id="last-logined-ip">$last_login->{ip}</dd>
</dl>

<div class="panel panel-default">
  <div class="panel-heading">
    お客様ご契約ID：$last_login->{login} 様の代表口座
  </div>
  <div class="panel-body">
    <div class="row">
      <div class="col-sm-4">
        普通預金<br>
        <small>東京支店　1111111111</small><br>
      </div>
      <div class="col-sm-4">
        <p id="zandaka" class="text-right">
          ―――円
        </p>
      </div>

      <div class="col-sm-4">
        <p>
          <a class="btn btn-success btn-block">入出金明細を表示</a>
          <a class="btn btn-default btn-block">振込・振替はこちらから</a>
        </p>
      </div>

      <div class="col-sm-12">
        <a class="btn btn-link btn-block">定期預金・住宅ローンのお申込みはこちら</a>
      </div>
    </div>
  </div>
</div>
__TEMPLATE__
}

filter 'session' => sub {
    my ($app) = @_;
    sub {
        my ($self, $c) = @_;
        my $sid = $c->req->env->{'psgix.session.options'}->{id};
        $c->stash->{session_id} = $sid;
        $c->stash->{session}    = $c->req->env->{'psgix.session'};
        $app->($self, $c);
    };
};

get '/' => [qw(session)] => sub {
    my ($self, $c) = @_;

    return $c->render_html_index($self->pop_flash($c));
};

post '/login' => sub {
    my ($self, $c) = @_;
    my $msg;

    my ($user, $err) = $self->attempt_login(
        $c->req->param('login'),
        $c->req->param('password'),
        $c->req->address
    );

    if ($user && $user->{id}) {
        $c->req->env->{'psgix.session'}->{user_id} = $user->{id};
        $c->redirect('/mypage');
    }
    else {
        if ($err eq 'locked') {
            $self->set_flash($c, 'This account is locked.');
        }
        elsif ($err eq 'banned') {
            $self->set_flash($c, "You're banned.");
        }
        else {
            $self->set_flash($c, 'Wrong username or password');
        }
        $c->redirect('/');
    }
};

get '/mypage' => [qw(session)] => sub {
    my ($self, $c) = @_;
    my $user_id = $c->req->env->{'psgix.session'}->{user_id};
    my $user = $self->current_user($user_id);
    my $msg;

    if ($user) {
        return $c->render_html_mypage($self->last_login($user_id));
    }
    else {
        $self->set_flash($c, "You must be logged in");
        return $c->redirect('/');
    }
};

get '/report' => sub {
    my ($self, $c) = @_;
    $c->render_json({
        banned_ips => $self->banned_ips,
        locked_users => $self->locked_users,
    });
};

1;
