# SPDX-License-Identifier: GPL-3.0-or-later

# THIS IS NOT A COMPLETE Makefile
# IT IS INCLUDED BY ITS PARENT'S Makefile.am
# IT IS REQUIRED TO REFERENCE ALL FILES RELATIVE TO THE PARENT

# install these files
dist_python_DATA       += kerio_connect/kerio_connect.chart.py
dist_pythonconfig_DATA += kerio_connect/kerio_connect.conf

# do not install these files, but include them in the distribution
dist_noinst_DATA       += kerio_connect/README.md kerio_connect/Makefile.inc

