#!/usr/bin/ksh

PROG=$0

function usage {
    cat <<EOF
Usage: ${PROG##*/} [options] [-- configure options]
        Use --built to package up a built version.
EOF
    exit ${1:-1}
}

function pkg_arch {
    typeset bitness
    bitness=$1
    if i386; then
        case "$bitness" in
        32) echo i386;;
        64) echo amd64;;
        *) exit 99
        esac
    elif sparc; then
        case "$bitness" in
        32) echo sparc;;
        64) echo sparcv9;;
        *) exit 99
        esac
    else
        printf 'Error: Unknown architecture %s\n' "$(uname -mpi)"
        exit 99
    fi
}

check=true
built=false
build32=false
build64=false
srcdir=
objdir=
builddir=
pkgname=heimdal
while [[ $# -gt 0 ]]; do
    case "$1" in
    -x) set -x;;
    --32) build32=true;;
    --64) build64=true;;
    --pkginfo) pkginfo=${2}; shift;;
    --pkginfo=*) pkginfo=${1#*=};;
    --built) built=true; builddir=${2}; shift;;
    --built=*) built=true; builddir=${1#*=};;
    --pkgname) pkgname=${2}; shift;;
    --pkgname=*) pkgname=${1#*=};;
    --srcdir) srcdir=${2}; shift;;
    --srcdir=*) srcdir=${1#*=};;
    --objdir) objdir=${2}; shift;;
    --objdir=*) objdir=${1#*=};;
    --nocheck|--nocheck=*) check=false;;
    --) shift; break;;
    -h|--help) ; usage 0;;
    *) usage;;
    esac
    shift
done

: ${builddir:=$objdir}
: ${objdir:=$builddir}

if ! $build32 && ! $build64; then
    build32=true
    build64=true
fi

set -e

base=${0%/*}
base=$(cd "$base" && pwd)

: ${srcdir:=$(cd "$base/../.." && pwd)}
: ${objdir:=$base}
: ${pkginfo:=$base/pkginfo}

config=${srcdir}/configure
destdir=${objdir}/destdir
imgdir=${objdir}/imgdir
unset pkgs

builddir32=
builddir64=
if $built; then
    if [[ "$(file "$builddir/kuser/.libs/kinit")" = *ELF\ 32* ]]; then
        builddir32=$builddir
    elif [[ "$(file "$builddir/kuser/.libs/kinit")" = *ELF\ 62* ]]; then
        builddir64=$builddir
    fi
else
    builddir32=$objdir/build32
    builddir64=$objdir/build64
fi

for var in built base objdir srcdir config builddir builddir32 builddir64 destdir imgdir; do
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

if $built && [[ ! -d "${builddir32}" && ! -d "${builddir64}" ]]; then
    printf "Error: --built given but neither $builddir32 nor $builddir64 exist\n"
    exit 1
fi

version=$(sh ${config} --help 2>/dev/null | head -1 | sed 's/.*Heimdal \([^ ]*\).*/\1/')

> log

for bitness in 32 64; do
    case $bitness in
    32) cd "${builddir32}"
        CFLAGS="-m32 -g -O0"
        $build32 || continue;;
    64) cd "${builddir64}"
        CFLAGS="-m64 -g -O0"
        pkgname=${pkgname}64
        $build64 || continue;;
    *) exit 99;;
    esac

    arch=$(pkg_arch $bitness)

    if ! $built; then
        echo "Building Solaris ${bitness}-bit SVR4 package for Heimdal ${version}"
        echo "Configure"
        env CFLAGS="$CFLAGS" \
          ${config} --srcdir="$srcdir" --disable-dependency-tracking "$@"
        echo "Build 32-bit"
        make all > /dev/null
        if $check; then
            echo "Run regression suite"
            make check > /dev/null
        fi
    fi

    echo "Install into DESTDIR=${destdir}"
    make install DESTDIR="${destdir}" > /dev/null
    echo "Package"
    grep -v '^PKG=' "$pkginfo" > "$objdir/pkginfo"
    printf 'PKG=%s\n' "$pkgname" >> "$objdir/pkginfo"
    # XXX Make copyright file
    pkgmk -a sparc -v "$(uname -r)--$version" -d "$imgdir" -f <(
        printf 'i pkginfo=$OBJDIR/pkginfo\n'
        printf 'i copyright=$SRCDIR/packages/solaris-svr4/copyright\n'
        pkgproto "${destdir}/${prefix}=${prefix}"
    ) SRCDIR="$srcdir" OBJDIR="$objdir" "${pkgname}"
    pkgtrans -s "$imgdir" "${imgdir}/${pkgname}.pkg" ${pkgname}
    pkgs[${#pkgs[@]}]=${imgdir}/${pkgname}.pkg
    echo "Package (${pkgname}) available in: ${imgdir} and ${imgdir}/${pkgname}.pkg"
done

echo "Done!"

echo "Packages available in: ${pkgs[*]}"

exit 0
