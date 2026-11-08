# Build eszközök telepítése
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y sbuild mmdebstrap uidmap dpkg-dev ca-certificates

# Builder user létrehozása (jelszó nélkül)
useradd -m -U -s /bin/bash builder

# Builder könyvtárak létrehozása
install -d -o builder -g builder /home/builder/.config/sbuild
install -d -o builder -g builder /home/builder/.cache/sbuild
install -d -o builder -g builder /home/builder/nginx-build

# sbuild unshare konfigurálása
printf '%s\n' \
  '$chroot_mode = "unshare";' \
  '$unshare_tmpdir_template = "/var/tmp/tmp.sbuild.XXXXXXXXXX";' \
  '1;' > /home/builder/.config/sbuild/config.pl

chown builder:builder /home/builder/.config/sbuild/config.pl

# Tiszta Debian 13 build chroot elkészítése
runuser -u builder -- env TMPDIR=/var/tmp mmdebstrap \
  --mode=unshare \
  --variant=buildd \
  --include=ca-certificates \
  --skip=output/dev \
  trixie \
  /home/builder/.cache/sbuild/trixie-amd64.tar.zst \
  https://deb.debian.org/debian

# Nginx source package letöltése
runuser -u builder -- sh -c \
  'cd /home/builder/nginx-build && apt-get source nginx'

# Nginx újrafordítása izolált chrootban
runuser -u builder -- sh -c \
  'cd /home/builder/nginx-build && sbuild --chroot-mode=unshare --chroot=/home/builder/.cache/sbuild/trixie-amd64.tar.zst -d trixie nginx_*.dsc'

# Elkészült csomagok
ls -lh /home/builder/*.deb
