#!/usr/bin/ksh

#--prefix=/opt/SEheimdal --srcdir=/export/home/nico/heimdal --with-berkeley-db CFLAGS="-g -O0" CPPFLAGS=-I/opt/SEdb2/BerkeleyDB/include/ LDFLAGS="-L/opt/SEdb2/BerkeleyDB/lib -R/opt/SEdb2/BerkeleyDB/lib -L/lib -R/lib -L/opt/csw -R/opt/csw -L/opt/sfw/lib -R/opt/sfw/lib -R/opt/csw/gcc4/lib"

# XXX Add --notest option?
if [[ "$1" = --help ]]; then
    cat <<EOF
Usage: ${0##*/} [--built] [configure options]
        Use --built to package up a built version.
EOF
    exit 1
fi

check=true
built=false
builddir=
while [[ $# -gt 0 ]]; do
    case "$1" in
    -x) set -x; shift;;
    --built|--built=*) built=true; builddir=${1#*=}; shift;;
    --nocheck|--nocheck=*) check=false; shift;;
    *) break;;
    esac
done

set -e

base=${0%/*}
base=$(cd "$base" && pwd)

srcdir=$(cd "$base/../.." && pwd)
config=${srcdir}/configure

destdir=${base}/destdir
builddir32=${base}/builddir32
builddir64=${base}/builddir64
imgdir=${base}/imgdir
unset pkgs

if [[ -d "$builddir" ]]; then
    if [[ "$(file "$builddir/kuser/.libs/kinit")" = *ELF\ 32* ]]; then
        builddir32=$builddir
    elif [[ "$(file "$builddir/kuser/.libs/kinit")" = *ELF\ 62* ]]; then
        builddir64=$builddir
    fi
fi

for var in built base srcdir config builddir builddir32 builddir64 destdir imgdir; do
    eval val=\$$var
    printf "%s=%s\n" "$var" "$val"
done

prefix=/usr
for arg in "$@"; do
    [[ "$arg" = --prefix=* ]] || continue
    prefix=${arg#--prefix=}
    break
done

rm -rf "${destdir}" "${imgdir}"
$built || echo rm -rf "${builddir32}" "${builddir64}"
mkdir "${destdir}"
$built || mkdir "${builddir32}"
$built || mkdir "${builddir64}"
mkdir "${imgdir}"

if [[ ! -d "${builddir32}" && ! -d "${builddir64}" ]]; then
    printf "Error: --built given but neither $builddir32 nor $builddir64 exist\n"
    exit 1
fi

if [[ -d "${builddir32}" ]]; then
    cd "${builddir32}"
    version=$(sh ${config} --help 2>/dev/null | head -1 | sed 's/.*Heimdal \([^ ]*\).*/\1/')

    if ! $built; then
        echo "Building Solaris 32-bit SVR4 package for Heimdal ${version}"
        echo "Configure"
        env \
          CFLAGS="-m32 -g -O0" \
          ${config} --srcdir="$srcdir" --disable-dependency-tracking "$@" > log
        echo "Build 32-bit"
        make all > /dev/null
        if $check; then
            echo "Run regression suite"
            make check > /dev/null
        fi
    fi
    echo "Install"
    set -x
    make install DESTDIR="${destdir}" > /dev/null
    echo "Package"
    pkgmk -a sparc -v "$(uname -r)--$version" -d "$imgdir" -f <(
        printf 'i pkginfo=$SRCDIR/packages/solaris-svr4/pkginfo\n'
        printf 'i copyright=$SRCDIR/packages/solaris-svr4/copyright\n'
        pkgproto "${destdir}/${prefix}=${prefix}"
    ) SRCDIR="$srcdir" SEheimdal
    pkgtrans -s "$imgdir" "${imgdir}/SEheimdal.pkg" SEheimdal
    pkgs[${#pkgs[@]}]=${imgdir}
    pkgs[${#pkgs[@]}]=${imgdir}/SEheimdal.pkg
    echo "Package (SEheimdal) available in: ${imgdir} and ${imgdir}/SEheimdal.pkg"
fi

if [[ -d "${builddir64}" ]]; then
    cd ${builddir64}
    version=$(sh ${config} --help 2>/dev/null | head -1 | sed 's/.*Heimdal \([^ ]*\).*/\1/')

    if ! $build; then
        echo "Building Solaris 64-bit SVR4 package for Heimdal ${version}"
        echo "Configure"
        env \
          CFLAGS="-m64 -g -O0" \
          "${config}" --srcdir="$srcdir" --disable-dependency-tracking "$@" > log
        echo "Build 64-bit"
        make all > /dev/null
        if $check; then
            echo "Run regression suite"
            make check > /dev/null
        fi
    fi
    echo "Install"
    make install DESTDIR="${destdir}" > /dev/null
    pkgmk -a sparcv9 -v "$(uname -r)--$version" -d "$imgdir" -f <(
        printf 'i pkginfo=$SRCDIR/packages/solaris-svr4/pkginfo\n'
        printf 'i copyright=$SRCDIR/packages/solaris-svr4/copyright\n'
        pkgproto "${destdir}/${prefix}=${prefix}"
    ) SRCDIR="$srcdir" SEheimdal64
    pkgs[${#pkgs[@]}]=${imgdir}
    pkgs[${#pkgs[@]}]=${imgdir}/SEheimdal.pkg
    echo "Package (SEheimdal64) available in: ${imgdir} and ${imgdir}/SEheimdal64.pkg"
fi

echo "Done!"

echo "Packages (SEheimdal SEheimdal64) available in: ${pkgs[*]}"

exit 0
