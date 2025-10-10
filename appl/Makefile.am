# $Id$

include $(top_srcdir)/Makefile.am.common

if DCE
dir_dce = dceutils
endif
if !NO_AFS
dir_afsutil = afsutil
endif
SUBDIRS = 					\
	  $(dir_afsutil)			\
	  dbutils				\
	  gssmask				\
	  test					\
	  kf					\
	  $(dir_dce)

EXTRA_DIST = NTMakefile
