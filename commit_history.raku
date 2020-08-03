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
            '"' ~ $s.subst(/'"'/, '\\"', :g) ~ '"';
        }

        ($.author.Str,
         $.timestamp.Str,
         esc-csv($.message.trim),
         esc-csv((@.filename.map(*.Str) Z @.revision.map({"($_.Str())"})).join(", "))).join(",");
    }
}

grammar LogGram {
    token tstamp {
        $<y>=(\d+) <[-/]>
        $<mo>=(\d+) <[-/]>
        $<d>=(\d+) \h+
        $<h>=(\d+) \:
        $<mn>=(\d+) \:
        $<s>=(\d+)
        $<tz>=(<[+-]> \d+)?

         { if $<tz> {
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

    token v {
        [\d|\.]+

        { make $/.Str.Version }
    }

    token logline {
        :my $*TRAILPRE = $*PREFIX.trim-trailing;
        ^^ <!before $*PREFIX <[Rr]>evision>
           [
           | $*PREFIX (\N*)
           | $*TRAILPRE \h* $$
           ]
        \n
#        { if $0 { say $0.Str.perl; prompt("?>") } }
        { make $0 ?? ~$0 !! "" }
    }

    proto token logentry {*}

    multi token logentry:<new> {
        ^^ $*PREFIX Revision \h+ <v> \h+ <tstamp> \h+ $<auth>=(\N+) \n
        <logline>*

        { make LogMessage.new(:timestamp($<tstamp>.ast)
                              :author(~$<auth>)
                              :revision($<v>.ast)
                              :message($<logline>.map(*.ast).join("\n"))) }
    }

    multi token logentry:<old> {
        ^^ $*PREFIX revision \h+ <v> \h+ "locked by:" \N+ \n
        ^^ $*PREFIX 'date:' \h+ <tstamp>';' \h+
                    'author:' \h+ $<auth>=([<![;]> \N]+)';'
                    \N+ \n
        <logline>*

        { make LogMessage.new(:timestamp($<tstamp>.ast)
                              :author(~$<auth>)
                              :revision($<v>.ast)
                              :message($<logline>.map(*.ast).join("\n"))) }
    }

    token logs {
        :my $*PREFIX;
        ^^ $<prefix>=([<![$]> \N]+) '$Log$' \n
        { $*PREFIX = ~$<prefix> }
        <logentry>*

        <!before $*PREFIX>

        { make $<logentry>».ast }
    }

    token pre-line {
        ^^ <!before [<![$]> \N]+ '$Log$' \n> \N* \n
    }

    token TOP {
        <.pre-line>*
        <logs>
        [\N* \n]*
        [\N* $]?

        { make $<logs>.ast }
    }
}

sub grab-logs(IO::Path $F, @logs) {
    die "$F.Str.perl() does not exist!" unless $F.e;
    die "$F.Str.perl() is not a regular file!" unless $F.f;

    # rakudo can't do EUC-JP, so we have to try encodings with iconv (This
    # assumes you have iconv.)

    my $res = run «iconv -feuc-jp -tutf8 "$F.absolute()"», :out :err;

    unless $res {
        # Shift-JIS perhaps?
        $res = run «iconv -fshift-jis -tutf8 "$F.absolute()"», :out :err;

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
    return unless $res ~~ /'$Log$'/;

    # try to find the log:
    die "\$Log\$ exists in $F.absolute() but couldn't parse" unless LogGram.parse($res);

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
            $last-msg = Empty;
        }
    }

    # in case list ends with trailing combination
    with $last-msg {
        $outfile.say: $last-msg.gist;
    }

#    $outfile.say: @logs.sort(*.timestamp).map(*.gist).join("\n");
    say "Done!";
}