XSLTPROC = xsltproc

EXTRA_DIST = $(HTMLS:../html/%.html=%.xml) \
	authors.xml notes.xml seealso.xml errorcodes.xml \
	transform-man.xsl.in transform-html.xsl.in

man_MANS = $(man1_MANS) $(man5_MANS)
HTMLS = $(man1_MANS:../man/man1/%.1=../html/%.html) $(man5_MANS:../man/man5/%.5=../html/%.html)

man1_MANS = \
	../man/man1/rolectl.1 \
	../man/man1/roled.1

man5_MANS = \
	../man/man5/rolekit.5 \
	../man/man5/rolekit.dbus.5 \
	../man/man5/rolekit.roles.5 \
	../man/man5/rolekit.roles.databaseserver.5 \
	../man/man5/rolekit.roles.domaincontroller.5 \
	../man/man5/rolekit.roles.memcache.5

CLEAN_FILES = *~ errorcodes.xml
DISTCLEANFILES = $(man_MANS) $(HTMLS) transform-*.xsl

#SGML_CATALOG_FILES
#XSLTPROC_FLAGS = --catalogs --nonet --xinclude
XSLTPROC_FLAGS = --nonet --xinclude 
XSLTPROC_MAN_FLAGS = $(XSLTPROC_FLAGS) transform-man.xsl
XSLTPROC_HTML_FLAGS = $(XSLTPROC_FLAGS) transform-html.xsl

install:

all: $(man_MANS) $(HTMLS)

clean:
	-test -z "$(CLEAN_FILES)" || rm -f $(CLEAN_FILES)

../man/man1/rolekitctl.1: errorcodes.xml

../html/rolekitctl.html: errorcodes.xml

../man/man1/%.1: %.xml authors.xml errorcodes.xml notes.xml seealso.xml transform-man.xsl
	$(XSLTPROC) -o $@ $(XSLTPROC_MAN_FLAGS) $<

../man/man5/%.5: %.xml authors.xml errorcodes.xml notes.xml seealso.xml transform-man.xsl
	$(XSLTPROC) -o $@ $(XSLTPROC_MAN_FLAGS) $<

../html/%.html: %.xml authors.xml notes.xml seealso.xml transform-html.xsl
	$(XSLTPROC) -o $@ $(XSLTPROC_HTML_FLAGS) $<

errorcodes.xml: ../../src/rolekit/errors.py
	@echo Creating $@
	@grep '=\s*[0-9]\+$$' ../../src/rolekit/errors.py | \
		sed -e 's/^/\<row\>\<entry\>/g' \
			-e 's/ *= */\<\/entry\>\<entry\>/g' \
			-e 's/$$/\<\/entry\>\<\/row\>/g' > $@

edit = sed \
	-e 's|\@PREFIX\@|$(prefix)|' \
	-e 's|\@SYSCONFDIR\@|$(sysconfdir)|' \
	-e 's|\@PACKAGE_STRING\@|$(PACKAGE_STRING)|'

transform-man.xsl: transform-man.xsl.in
	$(edit) $< >$@
transform-html.xsl: transform-html.xsl.in
	$(edit) $< >$@
