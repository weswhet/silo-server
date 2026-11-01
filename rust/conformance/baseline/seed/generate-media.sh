#!/bin/sh
# Writes the sample library into /media. Runs inside the baseline image so the
# ffmpeg build, and therefore every output byte, comes from that image.
set -eu

BITEXACT="-fflags +bitexact -flags:v +bitexact -flags:a +bitexact -map_metadata -1 -threads 1"
# Fixed so scanners that key on modification time see the same value each reset.
MTIME=202601010000

clip() { # clip <path> <seconds> <test-source> <sine-hz>
  mkdir -p "$(dirname "$1")"
  ffmpeg -nostdin -hide_banner -loglevel error -y \
    -f lavfi -i "$3=duration=$2:size=640x360:rate=24" \
    -f lavfi -i "sine=frequency=$4:duration=$2:sample_rate=48000" \
    -c:v libx264 -preset ultrafast -pix_fmt yuv420p -x264-params threads=1 \
    -c:a aac -b:a 64k -ac 2 \
    $BITEXACT "$1"
}

rm -rf /media/movies /media/tv

clip "/media/movies/Conformance Alpha (2001)/Conformance Alpha (2001).mp4" 12 testsrc 440
clip "/media/movies/Conformance Beta (2002)/Conformance Beta (2002).mkv" 12 testsrc2 660
clip "/media/tv/Conformance Show (2020)/Season 01/Conformance Show - S01E01.mkv" 8 testsrc 330
clip "/media/tv/Conformance Show (2020)/Season 01/Conformance Show - S01E02.mkv" 8 testsrc2 550

cat > "/media/movies/Conformance Alpha (2001)/Conformance Alpha (2001).en.srt" <<'SRT'
1
00:00:00,500 --> 00:00:02,500
Conformance sample subtitle.
SRT

# Local metadata, read by the builtin NFO provider, so items get real titles and
# overviews with no metadata plugin or network.
cat > "/media/movies/Conformance Alpha (2001)/Conformance Alpha (2001).nfo" <<'NFO'
<?xml version="1.0" encoding="UTF-8"?>
<movie>
  <title>Conformance Alpha</title>
  <originaltitle>Conformance Alpha</originaltitle>
  <year>2001</year>
  <plot>First synthetic movie for API comparison.</plot>
  <mpaa>PG</mpaa>
  <runtime>1</runtime>
  <genre>Drama</genre>
  <genre>Documentary</genre>
  <uniqueid type="tmdb" default="true">9000001</uniqueid>
  <actor><name>Fixture Actor</name><role>Lead</role><order>0</order></actor>
</movie>
NFO
cat > "/media/movies/Conformance Beta (2002)/Conformance Beta (2002).nfo" <<'NFO'
<?xml version="1.0" encoding="UTF-8"?>
<movie>
  <title>Conformance Beta</title>
  <year>2002</year>
  <plot>Second synthetic movie for API comparison.</plot>
  <mpaa>R</mpaa>
  <runtime>1</runtime>
  <genre>Comedy</genre>
  <uniqueid type="tmdb" default="true">9000002</uniqueid>
</movie>
NFO
cat > "/media/tv/Conformance Show (2020)/tvshow.nfo" <<'NFO'
<?xml version="1.0" encoding="UTF-8"?>
<tvshow>
  <title>Conformance Show</title>
  <year>2020</year>
  <plot>Synthetic series for API comparison.</plot>
  <mpaa>TV-PG</mpaa>
  <genre>Drama</genre>
  <uniqueid type="tvdb" default="true">9000003</uniqueid>
</tvshow>
NFO
cat > "/media/tv/Conformance Show (2020)/Season 01/Conformance Show - S01E01.nfo" <<'NFO'
<?xml version="1.0" encoding="UTF-8"?>
<episodedetails>
  <title>Pilot</title>
  <season>1</season>
  <episode>1</episode>
  <plot>First synthetic episode.</plot>
  <aired>2020-01-01</aired>
  <runtime>1</runtime>
  <uniqueid type="tvdb" default="true">9000011</uniqueid>
</episodedetails>
NFO
cat > "/media/tv/Conformance Show (2020)/Season 01/Conformance Show - S01E02.nfo" <<'NFO'
<?xml version="1.0" encoding="UTF-8"?>
<episodedetails>
  <title>Second</title>
  <season>1</season>
  <episode>2</episode>
  <plot>Second synthetic episode.</plot>
  <aired>2020-01-08</aired>
  <runtime>1</runtime>
  <uniqueid type="tvdb" default="true">9000012</uniqueid>
</episodedetails>
NFO

# Sidecar artwork from a single test frame.
poster() { # poster <path> <test-source>
  ffmpeg -nostdin -hide_banner -loglevel error -y \
    -f lavfi -i "$2=duration=1:size=200x300:rate=1" -frames:v 1 \
    -fflags +bitexact -flags:v +bitexact -threads 1 "$1"
}
poster "/media/movies/Conformance Alpha (2001)/poster.jpg" testsrc
poster "/media/movies/Conformance Beta (2002)/poster.jpg" testsrc2
poster "/media/tv/Conformance Show (2020)/poster.jpg" smptebars

find /media -exec touch -t "$MTIME" {} +
cd /media && find . -type f | LC_ALL=C sort | while IFS= read -r f; do sha256sum "$f"; done
