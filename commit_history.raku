# commit_history.raku -- extracts log messages from files in a directory and
#                        sorts them by timestamp

use v6;

#use Grammar::Debugger;

class LogMessage {
    has IO::Path @.filename is rw;
    has DateTime $.timestamp;
    has Str $.author;
    has Version @.revision is rw;
    has Str $.message;

    method header-line(LogMessage:_:) {
        Q{Author, Date, Message, Files affected (file revisions)}
    }

    multi method gist(LogMessage:D:) {
        sub esc-csv($s) {
            '"' ~ $s.subst(/'"'/, '""', :g) ~ '"';
        }

        ($.author.Str,
         $.timestamp.Str,
         esc-csv($.message.trim),
         esc-csv((@.filename.map(*.Str) Z @.revision.map({"($_.Str())"})).join(", "))).join(",");
    }
}

grammar LogGram {
    # critical to note that this grammar assumes C comments with logs don't
    # start on a line of code, e.g. "int i; /*\n$Log$ ...". If we tried being
    # super precise with what's allowed, then at some point we'd be writing a C
    # parser, and that's something you don't want.

    token TOP {
#        <.non-log>*

        [^^ <!log-set> \N* \n]*

        <log-set>

        [^^ \N* \n]*
        [^^ \N* $]?
    }

    token comment-start {
        | '/*'
        | '#' \h* <.log-intro>
    }

    token eol {
        $$ [\n || $]
    }

    token non-log {
        <!{$*IN_COMMENT}>
        ^^ \h* <!comment-start> \N* <.eol>
    }

    proto token log-set {*}

    multi token log-set:<c-star> {
        :my $*MODE = "C";

        :my $*WERE_PRE_LINES = False;
        :my $*BORDER = ""; # for top/bottom borders on comments
        ^^ \h* '/*' [<.cs-topborder> || \h* <.cs-earlyintro>]?
        [<.pre-cs-log-line> {$*WERE_PRE_LINES}]*
        [<!{$*WERE_PRE_LINES}> \h* | <.cs-linepre>] <.log-intro> \h* <.eol>
        <.cs-blank-line>*
        <commit-log>*
        <.post-cs-log-line>*
        <.post-cs-ending>
    }

    token cs-earlyintro {
        <!log-intro> [<!cs-end> \N]* <.eol> {$*WERE_PRE_LINES = True}
    }

    token cs-topborder {
        $<ch>=(<-alnum>) { $*BORDER = ~$<ch> }
        $*BORDER+ <.eol>
        { $*WERE_PRE_LINES = True }
    }

    token cs-linepre {
        ^^ \h* ['*' <![/]> \h*]?
    }

    # trailing '*' whitespace is not picked up here so that we can preserve
    # post-ident whitespace formatting
    token cs-log-linepre {
        ^^ \h* ['*' <![/]>]
    }

    token cs-end { '*/' }

    token pre-cs-log-line {
        <.cs-linepre> <!log-intro> [<!cs-end> \N]* <.eol>
    }

    token cs-blank-line { <.cs-linepre> <.eol> }

    token post-cs-log-line {
        <.cs-linepre> <!before <[rR]>evision»> [<!cs-end> \N]* <.eol>
    }

    token cs-bottom-border {
        <?{$*BORDER}> <.cs-linepre> $*BORDER+ <.cs-end> \N* <.eol>
    }

    token post-cs-ending {
        <.cs-linepre> [<!cs-end> \N]* <.cs-end> \N* <.eol>
    }

    multi token log-set:<bash> {
        :my $*MODE = "Bash";

        <.bash-linepre> <.log-intro> \h* <.eol>
        <.bash-blank-line>*
        <commit-log>*
    }

    token bash-linepre {
        ^^ \h* '#' \h*
    }

    # trailing '#' whitespace is not picked up here so that we can preserve
    # post-ident whitespace formatting
    token bash-log-linepre {
        ^^ \h* '#'
    }

    token bash-blank-line {
        ^^ \h* '#' \h* <.eol>
    }





    token LINE_PRE {
        || [
           | <?{$*MODE eq "C"}> <.cs-log-linepre>
           | <?{$*MODE eq "Bash"}> <.bash-log-linepre>
           ]
           # padding could be nothing, so empty string check won't work
           [
           | <?{$*PADDING.defined}> $*PADDING
           | <!{$*PADDING.defined}> (\h*) {$*PADDING = ~$0}
           ]
        || <!{$*MODE eq "C"|"Bash"}> { die "$*MODE unrecognized!" }
    }

    token BLANK_LINE {
        || [
           | <?{$*MODE eq "C"}> <.cs-blank-line>
           | <?{$*MODE eq "Bash"}> <.bash-blank-line>
           ]
        || <!{$*MODE eq "C"|"Bash"}> { die "$*MODE unrecognized!" }
    }

    token COMMENT_END {
        || <?{$*MODE eq "C"}> <.cs-end>
        || <!{$*MODE eq "C"|"Bash"}> { die "$*MODE unrecognized!" }
    }

    token BOTTOM_BORDER_OK {
        || <?{$*MODE eq "C"}> <.cs-bottom-border>
        || <!{$*MODE eq "C"|"Bash"}> { die "$*MODE unrecognized!" }
    }


    token log-intro { '$Log' [':' <-[$]>+]? '$' }

    proto token commit-log {*}

    token commit-log:<newstyle> {
        :my $*PADDING = Str;
        <.LINE_PRE> Revision \h+ <rev> \h+ <tstamp> \h+ $<auth>=(\N+) <.eol>
        <log-body>?
    }

    token commit-log:<oldstyle> {
        :my $*PADDING = Str;
        <.LINE_PRE> revision \h+ <rev> \h+ "locked by:" \N+ <.eol>
        <.LINE_PRE> 'date:' \h+ <tstamp> ';' \h+
                   'author:' \h+ $<auth>=([<![;]> \N]+) ';'
                   \N+ <.eol>
        <log-body>?
    }

    # extra \h* in before to deal with the next revision line being more indented
    token log-body {
        [
        | <.LINE_PRE> <!before \h* <[Rr]>evision»> ([<!COMMENT_END> \N]+) <.eol>
        | <.BLANK_LINE>
        ]+

        # just to see if I should bother being accomodating
        [ <!BOTTOM_BORDER_OK> <.LINE_PRE> [<!COMMENT_END> \N]+ <.COMMENT_END>
          { die "Comment ends on same line as message!" } ]?
    }

    token rev { [\d|\.]+ }

    token tstamp {
        $<y>=(\d+) <[-/]>
        $<mo>=(\d+) <[-/]>
        $<d>=(\d+) \h+
        $<h>=(\d+) \:
        $<mn>=(\d+) \:
        $<s>=(\d+)
        $<tz>=(<[+-]> \d+)?
    }
}

class LogActs {
    method TOP($/) {
        make $<log-set>.ast;
    }

    method log-set:<c-star>($/) {
        make $<commit-log>».ast;
    }

    method log-set:<bash>($/) {
        make $<commit-log>».ast;
    }

    method commit-log:<newstyle>($/) {
        make LogMessage.new(:timestamp($<tstamp>.ast)
                            :author(~$<auth>)
                            :revision($<rev>.ast)
                            :message($<log-body> ?? $<log-body>.ast !! ""));
    }

    method commit-log:<oldstyle>($/) {
        make LogMessage.new(:timestamp($<tstamp>.ast)
                            :author(~$<auth>)
                            :revision($<rev>.ast)
                            :message($<log-body> ?? $<log-body>.ast !! ""));
    }

    method log-body($/) {
        make $0.map(*.Str).join("\n");
    }

    method rev($/) { make $/.Str.Version }

    method tstamp($/) {
        if $<tz> {
            make DateTime.new(:year(+$<y>) :month(+$<mo>) :day(+$<d>)
                              :hour(+$<h>) :minute(+$<mn>) :second(+$<s>)
                              :timezone(+~$<tz> * 60 * 60));
        } else {
            # we base our decision on what timezone this unknown stamp is
            # based on the first iQue CVS commit's date.
            my $iQ = DateTime.new("2002-10-03T20:21:11Z");

            my $ifJ = DateTime.new(:year(+$<y>) :month(+$<mo>) :day(+$<d>)
                                   :hour(+$<h>) :minute(+$<mn>) :second(+$<s>)
                                   :timezone(9 * 60 * 60));

            my $ifC = DateTime.new(:year(+$<y>) :month(+$<mo>) :day(+$<d>)
                                   :hour(+$<h>) :minute(+$<mn>) :second(+$<s>)
                                   :timezone(8 * 60 * 60));

            if $ifJ >= $iQ && $ifC >= $iQ { # china time
                make $ifC;
            } elsif $ifJ < $iQ && $ifC < $iQ { # japan time
                make $ifJ;
            } else {
                die "Confused on time: C $ifC J $ifJ iQ $iQ";
            }
        }
    }
}

sub grab-logs(IO::Path $F, @logs) {
    die "$F.Str.perl() does not exist!" unless $F.e;
    die "$F.Str.perl() is not a regular file!" unless $F.f;

    # rakudo can't do EUC-JP, so we have to try encodings with iconv (This
    # assumes you have iconv.)

    my $res = run «iconv -f euc-jp -t utf-8 "$F.absolute()"», :out :err;

    unless $res {
        # Shift-JIS perhaps?
        $res = run «iconv -f shift-jis -t utf-8 "$F.absolute()"», :out :err;

        unless $res {
            #...maybe rakudo can handle it?
            try {
                $res = $F.slurp;

                CATCH {
                    default {
                        # skip this, must be binary
                        #note "$F.absolute() \e[33mis binary\e[0m";
                        return;
                    }
                }
            }
        }
    }

    unless $res ~~ Str {
        $res = $res.out.slurp(:close);
    }

    # if there is no $Log$, then skip this file
    return unless $res ~~ /'$Log' [':' <-[$]>+]? '$'/;

    # try to find the log:
    die "\$Log\$ line exists in $F.absolute() but couldn't parse" unless LogGram.parse($res, :actions(LogActs));

    for $/.ast {
        @logs.push($_);
        @logs[*-1].filename = $F;
    }
}

sub print-stats($stats, $pathstr) {
    my $colcode = 31;

    print "\r\e[K";

    for @$stats {
        NEXT { $colcode++; $colcode = 31 if $colcode > 36 }
        my $bright = "";
        # blue's hard to read for me, so brighten it
        $bright = ";1" if $colcode == 34;

        print "\e[0;{$colcode}{$bright}m[$_[0]/$_[1]]";
    }

    print "\e[0;1m $pathstr\e[0m";
}

sub descend(IO::Path $D, @logs, $stats = []) {
    die "$D.Str.perl() does not exist!" unless $D.e;
    die "$D.Str.perl() is not a directory!" unless $D.d;

    my $totdir = $D.dir.elems;

    for $D.dir {
        my @substats = @$stats;
        @substats.push: ((state $)++, $totdir);
        print-stats(@substats, $_.Str);
        if $_.d {
            descend($_, @logs, @substats);
        } elsif $_.f {
            grab-logs($_, @logs);
        } elsif $_.l {
            note "\r\e[K\e[33mWarning:\e[0m Broken symlink at \e[1m$_.Str()\e[0m";
        } else {
            die "$D.Str.perl() is a weird file type!";
        }
    }
}

sub MAIN(Str $dir, Bool :$new-first = False) {
    my $root = $dir.path;

    my $outfile = open("./outfile", :w);

    my @logs;

    descend($root, @logs);

    print "\r\e[K";

    $outfile.say: LogMessage.header-line;


    my $last-msg;

    for @logs.sort(*.timestamp) {
        if !$last-msg.defined {
            $last-msg = $_;
        } elsif $last-msg.timestamp eqv $_.timestamp
            && $last-msg.author eq $_.author
            && $last-msg.message eq $_.message {
                $last-msg.filename.append($_.filename);
                $last-msg.revision.append($_.revision);
        } else {
            $outfile.say: $last-msg.gist;
            $last-msg = $_; # bobby bench shogun
        }
    }

    # in case list ends with trailing combination
    with $last-msg {
        $outfile.say: $last-msg.gist;
    }

#    $outfile.say: @logs.sort(*.timestamp).map(*.gist).join("\n");
    say "Done!";
}