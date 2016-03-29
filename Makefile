
NAME=mod_intercept_form_submit

SOURCE0 := $(shell spectool $(NAME).spec)
SOURCE := $(shell echo $(SOURCE0) | sed 's%^.*/%%')
NAME_VER := $(shell echo $(SOURCE) | sed 's%\.tar\.gz$$%%')

all:
	@echo 'Usage: make dist             to build the .tar.gz'
	@echo '       make timestamps       set file timestamps to match commit times'

timestamps:
	git ls-files | while read -r f ; do touch -ch -d "$$(git log -1 --format=%ci "$$f")" "$$f" ; done

dist:
	@if test -f ../$(SOURCE) ; then ( echo "The source [../$(SOURCE)] already exists." >&2 ; exit 1 ) ; fi
	@mkdir .dist
	@mkdir .dist/$(NAME_VER) && cp -rp * .dist/$(NAME_VER)
	tar cvzf ../$(SOURCE) -C .dist $(NAME_VER)
	@rm -rf .dist

